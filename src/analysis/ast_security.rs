use crate::analysis::{ast, scanner};
#[cfg(test)]
use crate::rules::ast_fail_open_check;
use crate::rules::{
    rule_id, Severity, Violation, RE_API_FILE, RE_API_OR_ROUTE_FILE, RE_TEST_FILE,
    RE_TEST_ROUTE_SEGMENT,
};
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, BinaryExpression, BindingPattern,
    CallExpression, Expression, Function, LogicalExpression, MethodDefinition, ObjectProperty,
    Program, RegExpLiteral, ReturnStatement, Statement, StaticMemberExpression, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::Span;
use oxc_syntax::scope::ScopeFlags;
use std::collections::HashSet;

mod html;
mod math_random;
mod postmessage;
mod prototype_pollution;
mod server_io;
mod ssr_env;
mod test_route_guard;
mod unsafe_regex;

const USE_SERVER_DIRECTIVE: &str = "use server";
const USE_CLIENT_DIRECTIVE: &str = "use client";

/// Variable / function name substring (case-insensitive) が一致したら、
/// その文脈で使われる `Math.random()` を `Severity::Medium` で advisory する。
const MATH_RANDOM_SECURITY_KEYWORDS: [&str; 12] = [
    "token",
    "secret",
    "nonce",
    "sessionid",
    "userid",
    "apikey",
    "csrf",
    "salt",
    "uuid",
    "authtoken",
    "authkey",
    "privatekey",
];

fn is_bidi_char(ch: char) -> bool {
    matches!(ch, '\u{061C}' | '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn unwrap_parenthesized<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut current = expr;
    while let Expression::ParenthesizedExpression(p) = current {
        current = &p.expression;
    }
    current
}

/// `name` を ASCII-lowercase で fold して `MATH_RANDOM_SECURITY_KEYWORDS` のいずれかが
/// substring として含まれるかを判定する。JS identifier は概ね ASCII なので
/// `to_lowercase()` の per-call allocation を避けるためバイト走査で済ませる。
/// keyword 側は全て lowercase ASCII (上記定数を参照) なので比較は ASCII fold で十分。
fn name_matches_security_keyword(name: &str) -> bool {
    let bytes = name.as_bytes();
    MATH_RANDOM_SECURITY_KEYWORDS
        .iter()
        .any(|kw| ascii_fold_underscore_contains(bytes, kw.as_bytes()))
}

/// Return true when `haystack`, ASCII-lowercase folded and with `_` removed, contains `needle`
/// (already underscore-free lowercase ASCII) as a substring. So `api_key` matches `apikey`.
/// Shared with `ssr_env` (via `super::`) so security naming detection is uniform across rules;
/// keyword lists stay independent (see #304).
fn ascii_fold_underscore_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    for start in 0..haystack.len() {
        let mut hi = start;
        let mut ni = 0;
        while hi < haystack.len() && ni < needle.len() {
            let h = haystack[hi];
            if h == b'_' {
                hi += 1;
                continue;
            }
            if h.to_ascii_lowercase() != needle[ni] {
                break;
            }
            hi += 1;
            ni += 1;
        }
        if ni == needle.len() {
            return true;
        }
    }
    false
}

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    // Mirror production wiring (hook::lint_with_ast): check_bidi is a pure byte
    // scan that runs independent of parse success, so it lives outside the
    // parse closure. Keeping it here ensures unit tests exercise the same
    // fail-open behavior as production (see #294).
    let mut found = Vec::new();
    found.extend(check_bidi(content, file_path));
    found.extend(ast_fail_open_check(
        content,
        file_path,
        |program, line_offsets| check_program(program, line_offsets, file_path),
    ));
    found
}

#[cfg(test)]
fn check_js(code: &str) -> Vec<Violation> {
    check(code, "/src/app/api/users/route.ts")
}

pub fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
) -> Vec<Violation> {
    let is_api_file = RE_API_FILE.is_match(file_path);
    let has_top_level_use_server = !is_api_file && has_use_server_directive(&program.directives);
    let has_use_client = !is_api_file && has_use_client_directive(&program.directives);
    // SemanticBuilder (scope / symbol / reference resolution) is the heaviest
    // in-process step after parse, yet `scoping` feeds only the postMessage
    // origin check — and only when a message handler has an identifier param.
    // Pre-scan cheaply and build lazily so handler-less files (the majority)
    // skip it (#293). No other rule reads the symbol_id / reference_id Cells
    // this build populates, so skipping it is behavior-neutral elsewhere.
    let semantic = postmessage::requires_semantic(program)
        .then(|| SemanticBuilder::new().build(program).semantic);
    let scoping = semantic.as_ref().map(oxc_semantic::Semantic::scoping);
    let mut visitor = SecurityVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
        is_test_file: RE_TEST_FILE.is_match(file_path),
        is_api_or_route: RE_API_OR_ROUTE_FILE.is_match(file_path),
        // A route file (not a `.test.ts` unit test) whose path names a test segment.
        is_test_route: RE_API_OR_ROUTE_FILE.is_match(file_path)
            && !RE_TEST_FILE.is_match(file_path)
            && RE_TEST_ROUTE_SEGMENT.is_match(file_path),
        prod_env_guard_seen: false,
        is_server_context: is_api_file || has_top_level_use_server,
        has_top_level_use_server,
        use_server_depth: 0,
        in_direct_ssr_target: false,
        function_depth: 0,
        in_security_named_fn: false,
        has_use_client,
        scoping,
        cp_named_aliases: server_io::collect_cp_named_aliases(program),
    };
    visitor.visit_program(program);
    test_route_guard::emit_if_unguarded(&mut visitor);
    dedup_math_random_insecure(visitor.violations)
}

/// `MATH_RANDOM_INSECURE` だけを (rule, line) で重複排除する。`keyword_var` は
/// `decl.span`、`keyword_fn` は `call.span` で別 span を push するが、同一の
/// `Math.random()` を指すため同一 line に解決する (#297)。span でなく line 単位で
/// 畳む。同一 line の複数 push からは highest severity を残す (push 箇所には
/// `toString(36)` / crypto sink の High と keyword 系の Medium が混在し、keep-first だと
/// 並び次第で blocking High を Medium に潰す)。同 severity は先 push (handler 特異性順) を残す。
/// scope を本 rule に限定するのは、`SSR_SECRET_BLEED` のように 1 行で per-property に
/// 正当複数発火する rule を巻き込まないため。
fn dedup_math_random_insecure(violations: Vec<Violation>) -> Vec<Violation> {
    use std::collections::HashMap;
    // line -> 現時点で残す MATH_RANDOM_INSECURE の出力先 index
    let mut kept: HashMap<u32, usize> = HashMap::new();
    let mut dropped = vec![false; violations.len()];
    for (i, v) in violations.iter().enumerate() {
        if v.rule != rule_id::MATH_RANDOM_INSECURE {
            continue;
        }
        let Some(line) = v.line else {
            continue;
        };
        match kept.get(&line).copied() {
            None => {
                kept.insert(line, i);
            }
            Some(prev) if v.severity > violations[prev].severity => {
                dropped[prev] = true;
                kept.insert(line, i);
            }
            Some(_) => {
                dropped[i] = true;
            }
        }
    }
    violations
        .into_iter()
        .enumerate()
        .filter_map(|(i, v)| (!dropped[i]).then_some(v))
        .collect()
}

fn has_use_server_directive(directives: &[oxc_ast::ast::Directive]) -> bool {
    directives
        .iter()
        .any(|d| d.directive.as_str() == USE_SERVER_DIRECTIVE)
}

fn has_use_client_directive(directives: &[oxc_ast::ast::Directive]) -> bool {
    directives
        .iter()
        .any(|d| d.directive.as_str() == USE_CLIENT_DIRECTIVE)
}

// MAX_INPUT_SIZE (10 MB cap in main.rs) keeps `i` within u32::MAX, so the
// `i as u32` casts below cannot truncate.
#[allow(clippy::cast_possible_truncation)]
pub fn check_bidi(content: &str, file_path: &str) -> Option<Violation> {
    for (i, ch) in content.char_indices() {
        if is_bidi_char(ch) {
            // Build line offsets lazily: a bidi hit is rare (security
            // violation), so the per-edit hot path stays free of the newline
            // scan. check_bidi runs independent of parse success (see #294),
            // so it cannot reuse the offsets built inside with_parsed_program.
            let line_offsets = scanner::build_line_offsets(content);
            let line = ast::span_to_line(&line_offsets, Span::new(i as u32, i as u32));
            return Some(Violation {
                rule: rule_id::BIDI_CHARACTERS.to_owned(),
                severity: Severity::High,
                fix: "File contains Unicode bidirectional control characters (Trojan Source risk)."
                    .to_owned(),
                file: file_path.to_owned(),
                line: Some(line),
                origin: None,
            });
        }
    }
    None
}

struct SecurityVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
    is_test_file: bool,
    is_api_or_route: bool,
    // Test-named route file (`app/api/test-setup/route.ts` etc). When true and no
    // production guard is seen by walk's end, `test_route_guard::emit_if_unguarded`
    // pushes one advisory violation.
    is_test_route: bool,
    prod_env_guard_seen: bool,
    is_server_context: bool,
    has_top_level_use_server: bool,
    use_server_depth: u32,
    in_direct_ssr_target: bool,
    function_depth: u32,
    in_security_named_fn: bool,
    // File-level only; re-declarations in nested modules/components are out of scope.
    has_use_client: bool,
    // `None` when `check_program` skipped the SemanticBuilder (no identifier-param
    // message handler pre-scanned). Only the postMessage origin check reads it.
    scoping: Option<&'s Scoping>,
    // Local names bound by `import { <cp-fn> as <local> }` from a child-process
    // module, so `check_child_process` resolves the alias back to the API.
    cp_named_aliases: HashSet<String>,
}

impl SecurityVisitor<'_> {
    fn span_to_line(&self, span: Span) -> u32 {
        ast::span_to_line(self.line_offsets, span)
    }

    fn in_server_context(&self) -> bool {
        self.is_server_context || self.use_server_depth > 0
    }

    /// True when the current `Function` is itself a serialized SSR target —
    /// `getServerSideProps`, a `'use server'` directive body, or any function
    /// directly exported from a top-level `'use server'` file. False inside any
    /// nested helper, whose return is not sent to the client.
    fn is_ssr_target_function(&self, func: &Function) -> bool {
        if func
            .id
            .as_ref()
            .is_some_and(|id| id.name == "getServerSideProps")
        {
            return true;
        }
        if func
            .body
            .as_deref()
            .is_some_and(|b| has_use_server_directive(&b.directives))
        {
            return true;
        }
        self.has_top_level_use_server && self.function_depth == 0
    }

    fn push_violation(&mut self, rule: &str, severity: Severity, fix: &str, span: Span) {
        self.violations.push(Violation {
            rule: rule.to_owned(),
            severity,
            fix: fix.to_owned(),
            file: self.file_path.to_owned(),
            line: Some(self.span_to_line(span)),
            origin: None,
        });
    }
}

impl<'a> Visit<'a> for SecurityVisitor<'_> {
    fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
        self.check_html_assignment(expr);
        self.check_prototype_pollution(expr);
        self.check_onmessage_origin_missing(expr);
        walk::walk_assignment_expression(self, expr);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_err_stack(it);
        self.check_child_process(it);
        self.check_fs_path(it);
        self.check_non_literal_require(it);
        self.check_math_random_insecure(it);
        self.check_math_random_crypto_sink(it);
        self.check_math_random_keyword_fn(it);
        self.check_math_random_to_string_other(it);
        self.check_document_write(it);
        self.check_merge_pollution_sinks(it);
        self.check_postmessage_origin_missing(it);
        self.check_post_message_wildcard(it);
        walk::walk_call_expression(self, it);
    }

    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let prev_named = self.in_security_named_fn;
        if let Some(id) = &func.id {
            if name_matches_security_keyword(&id.name) {
                self.in_security_named_fn = true;
            }
        }
        let entered_use_server = func
            .body
            .as_deref()
            .is_some_and(|body| has_use_server_directive(&body.directives));
        if entered_use_server {
            self.use_server_depth += 1;
        }
        let prev_target = self.in_direct_ssr_target;
        self.in_direct_ssr_target = self.is_ssr_target_function(func);
        self.function_depth += 1;
        walk::walk_function(self, func, flags);
        self.function_depth -= 1;
        self.in_direct_ssr_target = prev_target;
        if entered_use_server {
            self.use_server_depth -= 1;
        }
        self.in_security_named_fn = prev_named;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let prev_target = self.in_direct_ssr_target;
        if self.function_depth > 0 {
            self.in_direct_ssr_target = false;
        }
        self.function_depth += 1;
        if self.in_direct_ssr_target && arrow.expression {
            if let Some(Statement::ExpressionStatement(expr_stmt)) = arrow.body.statements.first() {
                self.check_ssr_secret_object(&expr_stmt.expression);
            }
        }
        walk::walk_arrow_function_expression(self, arrow);
        self.function_depth -= 1;
        self.in_direct_ssr_target = prev_target;
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        let prev = self.in_security_named_fn;
        if let Some(name) = it.key.static_name() {
            if name_matches_security_keyword(&name) {
                self.in_security_named_fn = true;
            }
        }
        walk::walk_method_definition(self, it);
        self.in_security_named_fn = prev;
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        let prev = self.in_security_named_fn;
        if let Some(name) = it.key.static_name() {
            if name_matches_security_keyword(&name)
                && matches!(
                    &it.value,
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                )
            {
                self.in_security_named_fn = true;
            }
        }
        walk::walk_object_property(self, it);
        self.in_security_named_fn = prev;
    }

    fn visit_reg_exp_literal(&mut self, re: &RegExpLiteral<'a>) {
        self.check_unsafe_regex(re);
        walk::walk_reg_exp_literal(self, re);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.check_env_var_fallback(it);
        walk::walk_logical_expression(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.note_prod_guard(it);
        walk::walk_binary_expression(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        self.check_client_env_public_leak(it);
        walk::walk_static_member_expression(self, it);
    }

    fn visit_return_statement(&mut self, stmt: &ReturnStatement<'a>) {
        self.check_ssr_secret_bleed_return(stmt);
        walk::walk_return_statement(self, stmt);
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        self.check_math_random_keyword_var(decl);
        let prev_named = self.in_security_named_fn;
        if binds_security_named_function(decl) {
            self.in_security_named_fn = true;
        }
        let prev_target = self.in_direct_ssr_target;
        // Program-scope arrow / function expression bindings that ADR-0012 names
        // as SSR targets:
        // - `export const getServerSideProps = async () => ...` (Pages Router)
        // - any binding inside a top-level `'use server'` file (Server Action
        //   module; the file-as-whole is server-bundled, so every program-scope
        //   export is reachable as a Server Action target).
        if self.function_depth == 0
            && matches!(
                &decl.init,
                Some(Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_))
            )
            && (self.has_top_level_use_server
                || matches!(
                    &decl.id,
                    BindingPattern::BindingIdentifier(id) if id.name == "getServerSideProps"
                ))
        {
            self.in_direct_ssr_target = true;
        }
        walk::walk_variable_declarator(self, decl);
        self.in_direct_ssr_target = prev_target;
        self.in_security_named_fn = prev_named;
    }
}

/// `const generateToken = () => ...` のような「security-named binding に function/arrow 値を
/// 直接束縛する」VariableDeclarator のときのみ true。RHS が関数式でないケース
/// (例: `const token = Math.random()`) は false を返す。後者は
/// `check_math_random_keyword_var` 側で扱う。
fn binds_security_named_function(decl: &VariableDeclarator) -> bool {
    let BindingPattern::BindingIdentifier(ident) = &decl.id else {
        return false;
    };
    if !name_matches_security_keyword(&ident.name) {
        return false;
    }
    let Some(init) = &decl.init else {
        return false;
    };
    matches!(
        init,
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    )
}

#[cfg(test)]
mod tests;
