use crate::ast;
#[cfg(test)]
use crate::rules::ast_fail_open_check;
use crate::rules::{rule_id, Severity, Violation, RE_API_FILE, RE_API_OR_ROUTE_FILE, RE_TEST_FILE};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, ArrowFunctionExpression, AssignmentExpression,
    AssignmentTarget, BinaryOperator, BindingPattern, CallExpression, Expression, Function,
    LogicalExpression, LogicalOperator, MethodDefinition, ObjectProperty, ObjectPropertyKind,
    Program, RegExpLiteral, ReturnStatement, Statement, StaticMemberExpression, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::Span;
use oxc_syntax::scope::ScopeFlags;

mod math_random;
mod postmessage;
mod prototype_pollution;

// SECRET_KEY / SESSION_SECRET 等は SECRET の substring match で網羅される。
// KEY 単体は PUBLIC_KEY / SORT_KEY 等を誤検知するため除外し API_KEY のみ採用。
const SENSITIVE_ENV_KEYWORDS: [&str; 6] = [
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "JWT",
    "CREDENTIAL",
];

const CHILD_PROCESS_FNS: [&str; 4] = ["exec", "execSync", "spawn", "spawnSync"];

const USE_SERVER_DIRECTIVE: &str = "use server";
const USE_CLIENT_DIRECTIVE: &str = "use client";
const NEXT_PUBLIC_PREFIX: &str = "NEXT_PUBLIC_";

// NODE_ENV は React / Next.js / Webpack が client bundle に compile-time embed する
// 公式 public 値で、`process.env.NODE_ENV === 'production'` 形式の dev/prod 分岐は
// 一般的。NEXT_PUBLIC_ prefix と並ぶ allow 対象として明示する。
const CLIENT_ENV_ALLOW_LIST: [&str; 1] = ["NODE_ENV"];

// Underscore-free lowercase needles paired with `ascii_fold_underscore_contains`
// so `apiKey`, `API_KEY`, `db_token` all match the same `apikey` / `token` entry.
// Kept separate from `SENSITIVE_ENV_KEYWORDS` (used on the SCREAMING_SNAKE value
// side via plain `contains`) so each side can evolve independently.
const SSR_SECRET_KEYWORDS: [&str; 6] =
    ["secret", "token", "password", "apikey", "jwt", "credential"];

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
    matches!(ch, '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
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
        .any(|kw| ascii_fold_contains(bytes, kw.as_bytes()))
}

/// Return true when `name`, ASCII-lowercase folded and with `_` removed, contains any
/// `SSR_SECRET_KEYWORDS` entry as a substring. Targets SSR return-object property names
/// (`apiKey`, `API_KEY`, `db_token`, `password`, …) across camelCase, `snake_case` and
/// `SCREAMING_SNAKE` forms.
fn name_matches_ssr_secret_keyword(name: &str) -> bool {
    let bytes = name.as_bytes();
    SSR_SECRET_KEYWORDS
        .iter()
        .any(|kw| ascii_fold_underscore_contains(bytes, kw.as_bytes()))
}

/// Like `ascii_fold_contains` but treats `_` in the haystack as if it were not present,
/// so `API_KEY` matches `apikey`. The needle must already be underscore-free lowercase.
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

/// `haystack` を per-byte ASCII-lowercase で fold した結果に `needle` (lowercase ASCII) が
/// 含まれるか調べる。`needle.len() <= haystack.len()` のときのみ true を返す。
fn ascii_fold_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle)
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    ast_fail_open_check(content, file_path, |program, line_offsets| {
        let mut found = Vec::new();
        found.extend(check_bidi(content, file_path, line_offsets));
        found.extend(check_program(program, line_offsets, file_path));
        found
    })
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
    let semantic = SemanticBuilder::new().build(program).semantic;
    let mut visitor = SecurityVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
        is_test_file: RE_TEST_FILE.is_match(file_path),
        is_api_or_route: RE_API_OR_ROUTE_FILE.is_match(file_path),
        is_server_context: is_api_file || has_top_level_use_server,
        has_top_level_use_server,
        use_server_depth: 0,
        in_direct_ssr_target: false,
        function_depth: 0,
        in_security_named_fn: false,
        has_use_client,
        scoping: semantic.scoping(),
    };
    visitor.visit_program(program);
    visitor.violations
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
pub fn check_bidi(content: &str, file_path: &str, line_offsets: &[usize]) -> Option<Violation> {
    for (i, ch) in content.char_indices() {
        if is_bidi_char(ch) {
            let line = ast::span_to_line(line_offsets, Span::new(i as u32, i as u32));
            return Some(Violation {
                rule: rule_id::BIDI_CHARACTERS.to_owned(),
                severity: Severity::High,
                fix: "File contains Unicode bidirectional control characters (Trojan Source risk)."
                    .to_owned(),
                file: file_path.to_owned(),
                line: Some(line),
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
    is_server_context: bool,
    has_top_level_use_server: bool,
    use_server_depth: u32,
    in_direct_ssr_target: bool,
    function_depth: u32,
    in_security_named_fn: bool,
    // File-level only; re-declarations in nested modules/components are out of scope.
    has_use_client: bool,
    scoping: &'s Scoping,
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
        });
    }

    fn check_err_stack(&mut self, call: &CallExpression) {
        if !self.is_api_or_route {
            return;
        }
        if !is_response_call(&call.callee) {
            return;
        }
        for arg in &call.arguments {
            if arg_contains_stack(arg) {
                self.push_violation(
                    rule_id::ERR_STACK_EXPOSURE,
                    Severity::High,
                    "Use generic error message in production. Log stack trace server-side.",
                    call.span,
                );
                return;
            }
        }
    }

    fn check_child_process(&mut self, call: &CallExpression) {
        if !self.in_server_context() {
            return;
        }
        // KNOWN LIMITATION: aliased imports (import { exec as run }) are not detected.
        let name = match &call.callee {
            Expression::Identifier(id) => id.name.as_str(),
            Expression::StaticMemberExpression(sme) => sme.property.name.as_str(),
            Expression::ComputedMemberExpression(cme) => match &cme.expression {
                Expression::StringLiteral(s) => s.value.as_str(),
                _ => return,
            },
            _ => return,
        };
        if !CHILD_PROCESS_FNS.contains(&name) {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_string_literal_arg(first) {
            self.push_violation(
                rule_id::CHILD_PROCESS_INJECTION,
                Severity::High,
                "Use string literal for command. Validate and sanitize dynamic input.",
                call.span,
            );
        }
    }

    fn check_fs_path(&mut self, call: &CallExpression) {
        if !self.in_server_context() {
            return;
        }
        let obj = match &call.callee {
            Expression::StaticMemberExpression(sme) => &sme.object,
            // KNOWN LIMITATION: only bare `fs` identifier matched — aliased imports not detected.
            Expression::ComputedMemberExpression(cme) => match &cme.expression {
                Expression::StringLiteral(_) => &cme.object,
                _ => return,
            },
            _ => return,
        };
        if !ast::is_ident(obj, "fs") {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_safe_path_arg(first) {
            self.push_violation(
                rule_id::NON_LITERAL_FS_PATH,
                Severity::Medium,
                "Use string literal for file path. Validate against path traversal.",
                call.span,
            );
        }
    }

    fn check_non_literal_require(&mut self, call: &CallExpression) {
        if !self.in_server_context() {
            return;
        }
        let Expression::Identifier(id) = &call.callee else {
            return;
        };
        if id.name != "require" {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_string_literal_arg(first) {
            self.push_violation(
                rule_id::NON_LITERAL_REQUIRE,
                Severity::Medium,
                "Use string literal for require(). Dynamic require allows arbitrary code loading.",
                call.span,
            );
        }
    }

    fn check_unsafe_regex(&mut self, re: &RegExpLiteral) {
        let pattern = re.regex.pattern.text.as_str();
        if has_nested_quantifiers(pattern) {
            self.push_violation(
                rule_id::UNSAFE_REGEX,
                Severity::Medium,
                "Regex has nested quantifiers vulnerable to ReDoS. Simplify or use atomic groups.",
                re.span,
            );
        }
    }

    // Flags only `process.env.X || "literal"`. Identifier-bound fallbacks are
    // intentionally skipped so the violation message cannot double as a bypass hint.
    fn check_env_var_fallback(&mut self, expr: &LogicalExpression) {
        if !matches!(
            expr.operator,
            LogicalOperator::Coalesce | LogicalOperator::Or
        ) {
            return;
        }
        let Expression::StringLiteral(s) = &expr.right else {
            return;
        };
        if s.value.is_empty() {
            return;
        }
        let Some(name) = process_env_access_name(&expr.left) else {
            return;
        };
        if !SENSITIVE_ENV_KEYWORDS.iter().any(|kw| name.contains(kw)) {
            return;
        }
        self.push_violation(
            rule_id::ENV_VAR_FALLBACK,
            Severity::High,
            "Throw an error when required env var is missing. Never fall back to a hardcoded secret.",
            expr.span,
        );
    }

    fn check_client_env_public_leak(&mut self, sme: &StaticMemberExpression) {
        if !self.has_use_client {
            return;
        }
        if self.use_server_depth > 0 {
            return;
        }
        let Some(name) = process_env_access_name_from_sme(sme) else {
            return;
        };
        if name.starts_with(NEXT_PUBLIC_PREFIX) {
            return;
        }
        if CLIENT_ENV_ALLOW_LIST.contains(&name) {
            return;
        }
        self.push_violation(
            rule_id::CLIENT_ENV_PUBLIC_LEAK,
            Severity::High,
            "process.env in a 'use client' module is bundled to the browser. Move to a server component, or use a NEXT_PUBLIC_ prefix if the value is public.",
            sme.span,
        );
    }

    fn check_ssr_secret_bleed_return(&mut self, stmt: &ReturnStatement) {
        if !self.in_direct_ssr_target {
            return;
        }
        let Some(arg) = &stmt.argument else {
            return;
        };
        self.check_ssr_secret_object(arg);
    }

    /// Walk an SSR return value: for each direct property of an `ObjectExpression`,
    /// flag secret-named keys, flag `process.env.<SECRET>` values, otherwise recurse
    /// into nested object literals (so `{ props: { user: { token: ... } } }` and any
    /// other depth is reached). Non-object values and spread elements are skipped;
    /// variable-bound returns never reach here.
    fn check_ssr_secret_object(&mut self, expr: &Expression) {
        let expr = unwrap_parenthesized(expr);
        let Expression::ObjectExpression(obj) = expr else {
            return;
        };
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(op) = prop else {
                continue;
            };
            let Some(key_name) = op.key.static_name() else {
                continue;
            };
            if name_matches_ssr_secret_keyword(&key_name) {
                self.push_violation(
                    rule_id::SSR_SECRET_BLEED,
                    Severity::High,
                    "SSR/Server Action return is sent to the client. Move secret-named field server-side or rename if value is public.",
                    op.span,
                );
                continue;
            }
            if let Some(env_name) = process_env_access_name(&op.value) {
                if SENSITIVE_ENV_KEYWORDS
                    .iter()
                    .any(|kw| env_name.contains(kw))
                {
                    self.push_violation(
                        rule_id::SSR_SECRET_BLEED,
                        Severity::High,
                        "SSR/Server Action return is sent to the client. process.env secret leaks to the browser; return only render-needed data.",
                        op.span,
                    );
                    continue;
                }
            }
            self.check_ssr_secret_object(&op.value);
        }
    }

    fn check_html_assignment(&mut self, expr: &AssignmentExpression) {
        let AssignmentTarget::StaticMemberExpression(sme) = &expr.left else {
            return;
        };
        let (severity, fix) = match sme.property.name.as_str() {
            "innerHTML" => (
                Severity::High,
                "Use el.textContent = x for plain text, or el.innerHTML = DOMPurify.sanitize(x) when HTML is required",
            ),
            "outerHTML" => (
                Severity::Medium,
                "Use el.replaceWith(node) or el.outerHTML = DOMPurify.sanitize(html) instead of raw outerHTML assignment",
            ),
            _ => return,
        };
        if is_safe_html_value(&expr.right) {
            return;
        }
        self.push_violation(rule_id::UNSAFE_HTML_INJECTION, severity, fix, expr.span);
    }

    fn check_document_write(&mut self, call: &CallExpression) {
        let Expression::StaticMemberExpression(sme) = &call.callee else {
            return;
        };
        if !matches!(sme.property.name.as_str(), "write" | "writeln") {
            return;
        }
        if !ast::is_ident(&sme.object, "document") {
            return;
        }
        if call
            .arguments
            .first()
            .and_then(|a| a.as_expression())
            .is_some_and(is_safe_html_value)
        {
            return;
        }
        self.push_violation(
            rule_id::UNSAFE_HTML_INJECTION,
            Severity::High,
            "Use document.createElement(tag) + parent.appendChild(el) instead of document.write()",
            call.span,
        );
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

fn process_env_access_name<'a>(expr: &'a Expression) -> Option<&'a str> {
    let Expression::StaticMemberExpression(outer) = expr else {
        return None;
    };
    process_env_access_name_from_sme(outer)
}

fn process_env_access_name_from_sme<'a>(outer: &'a StaticMemberExpression) -> Option<&'a str> {
    let Expression::StaticMemberExpression(inner) = &outer.object else {
        return None;
    };
    if !ast::is_ident(&inner.object, "process") || inner.property.name != "env" {
        return None;
    }
    Some(outer.property.name.as_str())
}

fn is_response_call(callee: &Expression) -> bool {
    let (object, method) = match callee {
        Expression::StaticMemberExpression(sme) => (&sme.object, sme.property.name.as_str()),
        Expression::ComputedMemberExpression(cme) => match &cme.expression {
            Expression::StringLiteral(s) => (&cme.object, s.value.as_str()),
            _ => return false,
        },
        _ => return false,
    };
    if method != "json" && method != "send" {
        return false;
    }
    if ast::is_ident(object, "res") || ast::is_ident(object, "response") {
        return true;
    }
    let Expression::CallExpression(inner) = object else {
        return false;
    };
    let Expression::StaticMemberExpression(inner_sme) = &inner.callee else {
        return false;
    };
    inner_sme.property.name == "status"
        && (ast::is_ident(&inner_sme.object, "res") || ast::is_ident(&inner_sme.object, "response"))
}

fn arg_contains_stack(arg: &Argument) -> bool {
    match arg {
        Argument::SpreadElement(s) => spread_contains_stack(&s.argument),
        _ => arg.as_expression().is_some_and(|e| expr_contains_stack(e)),
    }
}

/// Spread of a bare identifier (e.g., `...err`) may copy a `.stack` property;
/// treat as unsafe in spread context only.
fn spread_contains_stack(expr: &Expression) -> bool {
    matches!(expr, Expression::Identifier(_)) || expr_contains_stack(expr)
}

fn expr_contains_stack(expr: &Expression) -> bool {
    match expr {
        Expression::StaticMemberExpression(sme) => {
            sme.property.name == "stack" || expr_contains_stack(&sme.object)
        }
        Expression::ObjectExpression(obj) => obj.properties.iter().any(|p| match p {
            ObjectPropertyKind::ObjectProperty(op) => expr_contains_stack(&op.value),
            ObjectPropertyKind::SpreadProperty(sp) => spread_contains_stack(&sp.argument),
        }),
        Expression::CallExpression(call) => call.arguments.iter().any(|a| arg_contains_stack(a)),
        Expression::ConditionalExpression(ce) => {
            expr_contains_stack(&ce.consequent) || expr_contains_stack(&ce.alternate)
        }
        Expression::LogicalExpression(le) => {
            expr_contains_stack(&le.left) || expr_contains_stack(&le.right)
        }
        Expression::ArrayExpression(arr) => arr.elements.iter().any(|el| match el {
            ArrayExpressionElement::SpreadElement(s) => spread_contains_stack(&s.argument),
            ArrayExpressionElement::Elision(_) => false,
            _ => el.as_expression().is_some_and(expr_contains_stack),
        }),
        Expression::TemplateLiteral(tl) => tl.expressions.iter().any(|e| expr_contains_stack(e)),
        _ => false,
    }
}

fn is_string_literal_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg
            .as_expression()
            .is_some_and(ast::is_static_template_literal),
    }
}

fn is_safe_path_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg.as_expression().is_some_and(is_static_path),
    }
}

fn is_safe_html_value(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) => true,
        _ if ast::is_static_template_literal(expr) => true,
        Expression::BinaryExpression(be) => {
            matches!(be.operator, BinaryOperator::Addition)
                && is_safe_html_value(&be.left)
                && is_safe_html_value(&be.right)
        }
        _ => false,
    }
}

fn is_static_path(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) => true,
        _ if ast::is_static_template_literal(expr) => true,
        Expression::Identifier(id) => id.name == "__dirname" || id.name == "__filename",
        Expression::BinaryExpression(be) => {
            matches!(be.operator, BinaryOperator::Addition)
                && is_static_path(&be.left)
                && is_static_path(&be.right)
        }
        _ => false,
    }
}

/// Skip past `[...]` in a regex pattern. `start` is the byte after `[`.
fn skip_char_class(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i] == b']' {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

// Group-depth bookkeeping uses a fixed 16-slot stack. Patterns nested
// deeper than 16 groups silently skip the inner-quantifier check (false
// negative); real-world ReDoS patterns rarely exceed that depth, and
// growing to a `Vec` only matters once a concrete pattern shows up.
fn has_nested_quantifiers(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut group_has_quantifier = [false; 16];
    let mut depth: usize = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' => {
                let Some(close) = skip_char_class(bytes, i + 1) else {
                    break;
                };
                i = close;
            }
            b'(' => {
                if depth < group_has_quantifier.len() {
                    group_has_quantifier[depth] = false;
                    depth += 1;
                }
                // Skip non-capturing/lookaround modifiers (?:, ?=, ?!, ?<)
                if i + 2 < bytes.len()
                    && bytes[i + 1] == b'?'
                    && matches!(bytes[i + 2], b':' | b'=' | b'!' | b'<')
                {
                    i += 2;
                }
            }
            b')' if depth > 0 => {
                depth -= 1;
                if group_has_quantifier[depth]
                    && i + 1 < bytes.len()
                    && matches!(bytes[i + 1], b'+' | b'*' | b'?' | b'{')
                {
                    return true;
                }
            }
            b'+' | b'*' | b'?' | b'{' if depth > 0 => {
                group_has_quantifier[depth - 1] = true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn err_stack_callee_variants() {
        for code in [
            "res.json({ stack: err.stack });",
            "res.status(500).json({ stack: error.stack });",
            "res.send({ stack: err.stack });",
            "response.json({ stack: err.stack });",
            "response.status(500).json({ error: err.stack });",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
            assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE, "failed for: {code}");
        }
    }

    #[test]
    fn non_response_callee_with_stack_safe() {
        assert!(check_js("logger.error({ stack: err.stack });").is_empty());
        assert!(check_js("console.error(err.stack);").is_empty());
    }

    #[test]
    fn res_json_without_stack_safe() {
        assert!(check_js("res.json({ error: err.message });").is_empty());
    }

    #[test]
    fn nested_stack_in_object() {
        let v = check_js("res.json({ data: { detail: err.stack } });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn stack_in_conditional() {
        let v = check_js("res.json({ error: isDev ? err.stack : 'error' });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn stack_in_logical() {
        let v = check_js("res.json({ error: err && err.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn stack_in_array() {
        let v = check_js("res.json([err.stack]);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn child_process_dynamic_arg_blocked() {
        for code in [
            "exec(userInput);",
            "execSync(cmd);",
            "spawn(variable, args);",
            "spawnSync(cmd, args);",
            "exec(`ls ${dir}`);",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::CHILD_PROCESS_INJECTION,
                "failed for: {code}"
            );
        }
    }

    #[test]
    fn child_process_literal_safe() {
        assert!(check_js("exec('ls -la');").is_empty());
        assert!(check_js("exec(`ls -la`);").is_empty());
        assert!(check_js("execFile('/usr/bin/git', args);").is_empty());
    }

    #[test]
    fn fs_dynamic_path_blocked() {
        for code in [
            "fs.readFile(userInput, cb);",
            "fs.writeFileSync(variable, data);",
            "fs.readFileSync(path.join(__dirname, f));",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(v[0].severity, Severity::Medium, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::NON_LITERAL_FS_PATH,
                "failed for: {code}"
            );
        }
    }

    #[test]
    fn fs_static_path_safe() {
        assert!(check_js("fs.readFile('./config.json', cb);").is_empty());
        assert!(check_js("fs.readFile(__dirname + '/file', cb);").is_empty());
        assert!(check_js("fs.readFile(__filename, cb);").is_empty());
        assert!(check_js("fs.readFile(__dirname + '/sub' + '/file', cb);").is_empty());
        assert!(check_js("fs.readFile(`./config.json`, cb);").is_empty());
    }

    #[test]
    fn fail_open_on_invalid_or_unsupported_input() {
        assert!(check_js("function { invalid syntax !!!").is_empty());
        assert!(check_js("").is_empty());
        assert!(check("body { color: red; }", "/src/styles.css").is_empty());
    }

    #[test]
    fn member_expression_callee_variants() {
        for (code, rule) in [
            (
                r#"cp["exec"](userInput);"#,
                rule_id::CHILD_PROCESS_INJECTION,
            ),
            ("cp.exec(userInput);", rule_id::CHILD_PROCESS_INJECTION),
            ("childProcess.spawn(cmd);", rule_id::CHILD_PROCESS_INJECTION),
            (
                r#"fs["readFile"](userInput, cb);"#,
                rule_id::NON_LITERAL_FS_PATH,
            ),
            (
                r#"res["json"]({ stack: err.stack });"#,
                rule_id::ERR_STACK_EXPOSURE,
            ),
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(v[0].rule, rule, "failed for: {code}");
        }
        assert!(check_js(r#"cp["exec"]("ls -la");"#).is_empty());
        assert!(check_js("cp.exec('ls -la');").is_empty());
    }

    #[test]
    fn fs_boundary_conditions() {
        let v = check_js("fs.readFile(__dirname + userInput, cb);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);

        let v = check_js("fs.unlink(variable, cb);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn stack_in_template_literal() {
        let v = check_js("res.json(`error: ${err.stack}`);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn known_limitations_not_detected() {
        assert!(check_js("fileSystem.readFile(userInput, cb);").is_empty());
        assert!(check_js("require('fs').readFile(userInput, cb);").is_empty());
    }

    #[test]
    fn stack_in_spread_contexts_blocked() {
        for code in [
            "res.json({ ...err });",
            "res.json([...err]);",
            "res.json(...args);",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
            assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE, "failed for: {code}");
        }
    }

    #[test]
    fn non_spread_identifier_property_safe() {
        assert!(check_js("res.json({ data: someVar });").is_empty());
    }

    #[test]
    fn zero_arg_calls_safe() {
        assert!(check_js("res.json();").is_empty());
        assert!(check_js("exec();").is_empty());
    }

    #[test]
    fn bidi_rlo_in_code_blocked() {
        let v = check_js("let x = '\u{202E}' + y;");
        assert_eq!(v.len(), 1, "should detect bidi char");
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
    }

    #[test]
    fn bidi_rli_in_comment_blocked() {
        let v = check_js("// comment with \u{2067} bidi\nlet x = 1;");
        assert_eq!(v.len(), 1, "should detect bidi in comments");
        assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
    }

    #[test]
    fn bidi_rlm_in_string_blocked() {
        let v = check_js("const s = \"hello\u{200F}world\";");
        assert_eq!(v.len(), 1, "should detect bidi in strings");
        assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
    }

    #[test]
    fn no_bidi_safe() {
        assert!(check_js("const x = 1;\nconst y = 2;").is_empty());
    }

    #[test]
    fn multiple_bidi_reports_first() {
        let v = check_js("let a = '\u{202E}';\nlet b = '\u{202D}';");
        assert_eq!(v.len(), 1, "should report only first bidi occurrence");
        assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
        assert_eq!(v[0].line, Some(1), "should report first line");
    }

    #[test]
    fn unsafe_regex_nested_quantifier_blocked() {
        let v = check_js("const re = /^(a+)+$/;");
        assert_eq!(v.len(), 1, "should detect nested quantifier");
        assert_eq!(v[0].severity, Severity::Medium);
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn unsafe_regex_digit_nested_blocked() {
        let v = check_js("const re = /^(\\d+)+$/;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn unsafe_regex_alternation_with_quantifier_blocked() {
        let v = check_js("const re = /^(a+|b+)*$/;");
        assert_eq!(v.len(), 1, "should detect quantifier in quantified group");
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn unsafe_regex_brace_quantifier_blocked() {
        // {n,} inside quantified group
        let v = check_js("const re = /^(\\d{2,}){3,}$/;");
        assert_eq!(
            v.len(),
            1,
            "should detect brace quantifier as inner quantifier"
        );
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn unsafe_regex_optional_in_quantified_group_blocked() {
        // (a?)+ — ? is a quantifier, star height 2
        let v = check_js("const re = /^(a?)+$/;");
        assert_eq!(v.len(), 1, "should detect ? as inner quantifier");
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn safe_regex_quantified_group_with_optional_outer() {
        // (a+)? — outer ? is bounded (0-1), but inner + is unbounded
        // This IS flagged because inner has +, outer has ?
        let v = check_js("const re = /^(a+)?$/;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn safe_regex_simple_quantifier() {
        assert!(check_js("const re = /^\\d+$/;").is_empty());
    }

    #[test]
    fn safe_regex_char_class_quantifier() {
        assert!(check_js("const re = /^[a-z]+$/;").is_empty());
    }

    #[test]
    fn safe_regex_quantifier_inside_char_class() {
        // + inside [...] is literal, not a quantifier
        assert!(check_js("const re = /^([a+])+$/;").is_empty());
    }

    #[test]
    fn safe_regex_escaped_quantifier() {
        let v = check_js("const re = /^(a\\+)+$/;");
        assert!(
            v.is_empty(),
            "escaped + should not be treated as quantifier"
        );
    }

    #[test]
    fn dynamic_regexp_not_analyzed() {
        assert!(check_js("const re = new RegExp(pattern);").is_empty());
    }

    #[test]
    fn safe_regex_non_capturing_group() {
        assert!(check_js("const re = /^(?:foo)+$/;").is_empty());
        assert!(check_js("const re = /^(?:a|b)+$/;").is_empty());
        assert!(check_js("const re = /^(?:ab)*$/;").is_empty());
    }

    #[test]
    fn safe_regex_lookaround_groups() {
        assert!(check_js("const re = /^(?=foo).+$/;").is_empty());
        assert!(check_js("const re = /^(?!foo).+$/;").is_empty());
        assert!(check_js("const re = /^(?<=foo).+$/;").is_empty());
        assert!(check_js("const re = /^(?<!foo).+$/;").is_empty());
    }

    #[test]
    fn unsafe_regex_nested_inside_non_capturing_group() {
        // (?:a+)+ — inner a+ is a real quantifier, outer + on group = nested
        let v = check_js("const re = /^(?:a+)+$/;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
    }

    #[test]
    fn non_literal_require_variable_blocked() {
        let v = check_js("const m = require(variable);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
    }

    #[test]
    fn require_string_literal_safe() {
        assert!(check_js("const m = require('./module');").is_empty());
    }

    #[test]
    fn require_static_template_safe() {
        assert!(check_js("const m = require(`./module`);").is_empty());
    }

    #[test]
    fn require_dynamic_template_blocked() {
        let v = check_js("const m = require(`./modules/${name}`);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
    }

    #[test]
    fn require_no_args_safe() {
        assert!(check_js("require();").is_empty());
    }

    #[test]
    fn p1_and_p2_violations_coexist() {
        let code = concat!(
            "exec(userInput);\n",
            "const m = require(variable);\n",
            "const re = /^(a+)+$/;\n",
            "res.json({ stack: err.stack });\n",
            "fs.readFile(userInput, cb);\n",
        );
        let v = check_js(code);
        let rules: Vec<&str> = v.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&rule_id::CHILD_PROCESS_INJECTION));
        assert!(rules.contains(&rule_id::NON_LITERAL_REQUIRE));
        assert!(rules.contains(&rule_id::UNSAFE_REGEX));
        assert!(rules.contains(&rule_id::ERR_STACK_EXPOSURE));
        assert!(rules.contains(&rule_id::NON_LITERAL_FS_PATH));
        assert!(v.len() >= 5, "expected at least 5, got {}", v.len());
    }

    // T-001: env_var_fallback_nullish_coalescing_jwt_secret_blocked
    #[test]
    fn env_var_fallback_nullish_coalescing_jwt_secret_blocked() {
        let v = check_js(r#"const s = process.env.JWT_SECRET ?? "fallback";"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-002: env_var_fallback_short_circuit_or_api_key_blocked
    #[test]
    fn env_var_fallback_short_circuit_or_api_key_blocked() {
        let v = check_js(r#"const k = process.env.API_KEY || "default";"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
    }

    // T-003: env_var_fallback_sensitive_keywords_all_blocked
    #[test]
    fn env_var_fallback_sensitive_keywords_all_blocked() {
        for code in [
            r#"const a = process.env.SECRET ?? "x";"#,
            r#"const b = process.env.AUTH_TOKEN ?? "x";"#,
            r#"const c = process.env.USER_PASSWORD ?? "x";"#,
            r#"const d = process.env.API_KEY ?? "x";"#,
            r#"const e = process.env.JWT ?? "x";"#,
            r#"const f = process.env.AWS_CREDENTIAL ?? "x";"#,
            r#"const g = process.env.SECRET_KEY ?? "x";"#,
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK, "failed for: {code}");
        }
    }

    // T-004: env_var_fallback_log_level_allowed
    #[test]
    fn env_var_fallback_log_level_allowed() {
        let v = check_js(r#"const l = process.env.LOG_LEVEL ?? "info";"#);
        assert_eq!(v.len(), 0);
    }

    // T-005: env_var_fallback_public_and_sort_keys_allowed
    #[test]
    fn env_var_fallback_public_and_sort_keys_allowed() {
        for code in [
            r#"const k = process.env.PUBLIC_KEY ?? "";"#,
            r#"const s = process.env.SORT_KEY || "asc";"#,
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 0, "failed for: {code}");
        }
    }

    // T-006: env_var_fallback_multiline_logical_expression_blocked
    #[test]
    fn env_var_fallback_multiline_logical_expression_blocked() {
        let v = check_js("const s = process.env.JWT_SECRET\n  ?? \"fallback\";");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
    }

    // T-016: env_var_fallback_fail_open_on_invalid_syntax
    #[test]
    fn env_var_fallback_fail_open_on_invalid_syntax() {
        let v = check_js("function { invalid !!!");
        assert_eq!(v.len(), 0);
    }

    // T-019: detects_inner_html_variable_assignment
    #[test]
    fn detects_inner_html_variable_assignment() {
        let v = check_js("el.innerHTML = userInput;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
        assert_eq!(v[0].severity, Severity::High);
        assert!(v[0].fix.contains("textContent"));
    }

    // T-019: allows_inner_html_string_literal
    #[test]
    fn allows_inner_html_string_literal() {
        assert!(check_js(r#"el.innerHTML = "<div>static</div>";"#).is_empty());
    }

    // T-019: allows_inner_html_static_template
    #[test]
    fn allows_inner_html_static_template() {
        assert!(check_js("el.innerHTML = `<div>static</div>`;").is_empty());
    }

    // T-019: detects_inner_html_template_with_expression
    #[test]
    fn detects_inner_html_template_with_expression() {
        let v = check_js("el.innerHTML = `<div>${userInput}</div>`;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    }

    // T-019: detects_inner_html_empty_string_concat (regex 版の known limitation を解消)
    #[test]
    fn detects_inner_html_empty_string_concat() {
        let v = check_js(r#"el.innerHTML = "" + userInput;"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    }

    // T-019: allows_inner_html_concat_of_literals
    #[test]
    fn allows_inner_html_concat_of_literals() {
        assert!(check_js(r#"el.innerHTML = "<div>" + "static" + "</div>";"#).is_empty());
    }

    // T-020: detects_outer_html_variable_assignment
    #[test]
    fn detects_outer_html_variable_assignment() {
        let v = check_js("el.outerHTML = userInput;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
        assert_eq!(v[0].severity, Severity::Medium);
        assert!(v[0].fix.contains("el.replaceWith(node)"));
    }

    // T-020: allows_outer_html_string_literal
    #[test]
    fn allows_outer_html_string_literal() {
        assert!(check_js(r#"el.outerHTML = "<span>text</span>";"#).is_empty());
    }

    // T-021: detects_document_write_variable
    #[test]
    fn detects_document_write_variable() {
        let v = check_js("document.write(userInput);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
        assert_eq!(v[0].severity, Severity::High);
        assert!(v[0].fix.contains("createElement"));
    }

    // T-021: detects_document_writeln_variable
    #[test]
    fn detects_document_writeln_variable() {
        let v = check_js("document.writeln(userInput);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-021: allows_document_write_literal
    #[test]
    fn allows_document_write_literal() {
        assert!(check_js(r#"document.write("<h1>hello</h1>");"#).is_empty());
    }

    // T-021: detects_document_write_concat_with_variable
    #[test]
    fn detects_document_write_concat_with_variable() {
        let v = check_js(r#"document.write("<h1>" + title + "</h1>");"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    }

    // T-021: ignores_unrelated_document_method
    #[test]
    fn ignores_unrelated_document_method() {
        assert!(check_js("document.getElementById('x');").is_empty());
        assert!(check_js("document.createElement('div');").is_empty());
    }

    // T-021: ignores_non_document_write
    #[test]
    fn ignores_non_document_write() {
        assert!(check_js("stream.write(userInput);").is_empty());
        assert!(check_js("logger.write(userInput);").is_empty());
    }

    // TC-007: document.write() with zero arguments is flagged. The absence of
    // a safe literal arg means `is_some_and(is_safe_html_value)` returns false,
    // matching the regex-parity behavior (regex also matched `document.write()`).
    #[test]
    fn detects_document_write_zero_args_intent() {
        let v = check_js("document.write();");
        assert_eq!(
            v.len(),
            1,
            "zero-arg document.write() intentionally flagged"
        );
        assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-018: nfr001_performance_under_10ms
    #[test]
    fn nfr001_performance_under_10ms() {
        let content = concat!(
            "const m = require('./ok');\n",
            "const n = require(variable);\n",
            "const re1 = /^(a+)+$/;\n",
            "const re2 = /^\\d+$/;\n",
            "exec('ls -la');\n",
            "exec(userInput);\n",
            "fs.readFile('./config.json', cb);\n",
            "fs.readFile(userInput, cb);\n",
            "res.json({ error: 'oops' });\n",
            "res.json({ stack: err.stack });\n",
            "const s = process.env.JWT_SECRET ?? 'fallback';\n",
            "const id = Math.random().toString(36).substring(2);\n",
            "el.innerHTML = userInput;\n",
            "el.outerHTML = `<span>${x}</span>`;\n",
            "document.write(userInput);\n",
            // TC-006: deeply-nested BinaryExpression to stress is_safe_html_value
            // recursive descent on the safe-static path (all string literals).
            "el.innerHTML = 'a' + 'b' + 'c' + 'd' + 'e' + 'f' + 'g' + 'h' + 'i' + 'j' + 'k' + 'l' + 'm' + 'n' + 'o' + 'p';\n",
            "obj[\"__proto__\"] = userInput;\n",
            "Object.assign(target, JSON.parse(input));\n",
            "_.merge(target, JSON.parse(input));\n",
            "const lookup = styleMap[variant];\n",
            "const token = Math.random();\n",
            "function generateSessionToken() { return Math.random(); }\n",
            "const fixed = Math.random().toFixed(8);\n",
        );
        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = check(content, "/src/app/api/handler/route.ts");
        }
        let elapsed = start.elapsed();
        let per_file_us = elapsed.as_micros() / iterations;
        eprintln!("NFR-001: {per_file_us}us/file ({iterations} iterations)");
        assert!(
            per_file_us < 10_000,
            "AST check exceeded 10ms/file: {per_file_us}us"
        );
    }

    #[test]
    fn err_stack_skipped_in_ui_component() {
        let v = check(
            "res.json({ stack: err.stack });",
            "/src/components/ErrorView.tsx",
        );
        assert!(v.is_empty(), "UI component must skip err-stack: {v:?}");
    }

    #[test]
    fn err_stack_skipped_in_util_file() {
        let v = check("res.json({ stack: err.stack });", "/src/utils/format.ts");
        assert!(v.is_empty(), "util must skip err-stack: {v:?}");
    }

    #[test]
    fn err_stack_detected_in_pages_api() {
        let v = check("res.json({ stack: err.stack });", "/src/pages/api/users.ts");
        assert_eq!(v.len(), 1, "pages/api must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn err_stack_detected_in_app_route() {
        let v = check(
            "export async function GET() { res.json({ stack: err.stack }); }",
            "/src/app/orders/[id]/route.ts",
        );
        assert_eq!(v.len(), 1, "app/**/route.ts must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn err_stack_skipped_when_only_use_server_no_api_path() {
        let v = check(
            "'use server';\nres.json({ stack: err.stack });",
            "/src/lib/helpers.ts",
        );
        assert!(v.is_empty(), "err-stack requires api/route path: {v:?}");
    }

    #[test]
    fn fs_path_skipped_in_ui_component() {
        let v = check("fs.readFile(userInput, cb);", "/src/components/View.tsx");
        assert!(v.is_empty(), "UI component must skip fs-path: {v:?}");
    }

    #[test]
    fn fs_path_skipped_in_util_file() {
        let v = check("fs.readFile(userInput, cb);", "/src/utils/loader.ts");
        assert!(v.is_empty(), "util must skip fs-path: {v:?}");
    }

    #[test]
    fn fs_path_detected_with_use_server_directive() {
        let v = check(
            "'use server';\nfs.readFile(userInput, cb);",
            "/src/lib/actions.ts",
        );
        assert_eq!(v.len(), 1, "use server must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn require_skipped_in_ui_component() {
        let v = check("require(variable);", "/src/components/View.tsx");
        assert!(v.is_empty(), "UI component must skip require: {v:?}");
    }

    #[test]
    fn require_detected_with_use_server_directive() {
        let v = check("'use server';\nrequire(variable);", "/src/lib/actions.ts");
        assert_eq!(v.len(), 1, "use server must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
    }

    #[test]
    fn child_process_skipped_in_ui_component() {
        let v = check("exec(userInput);", "/src/components/View.tsx");
        assert!(v.is_empty(), "UI component must skip exec: {v:?}");
    }

    #[test]
    fn child_process_detected_with_use_server_directive() {
        let v = check("'use server';\nexec(userInput);", "/src/lib/actions.ts");
        assert_eq!(v.len(), 1, "use server must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn detects_inline_use_server_inside_function_body() {
        let code = r"
            export async function submitForm(formData) {
                'use server';
                fs.readFile(formData.get('path'), cb);
            }
        ";
        let v = check(code, "/src/app/page.tsx");
        assert_eq!(v.len(), 1, "inline use server must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn inline_use_server_scope_exits_with_function() {
        let code = r"
            async function action() {
                'use server';
                require(modulePath);
            }
            fs.readFile(unsafePath, cb);
        ";
        let v = check(code, "/src/components/Form.tsx");
        assert_eq!(v.len(), 1, "only inner call flags: {v:?}");
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
    }

    #[test]
    fn err_stack_detected_in_root_app_route() {
        let v = check(
            "export async function GET() { res.json({ stack: err.stack }); }",
            "/src/app/route.ts",
        );
        assert_eq!(v.len(), 1, "root app/route.ts must flag: {v:?}");
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn client_env_leak_fires_with_use_client_directive() {
        let code = "\"use client\";\nconst key = process.env.SECRET_API_KEY;";
        let v = check(code, "/src/components/Profile.tsx");
        let leaks: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
            .collect();
        assert_eq!(leaks.len(), 1, "client env leak must flag: {v:?}");
        assert_eq!(leaks[0].severity, Severity::High);
    }

    #[test]
    fn client_env_leak_silent_on_next_public_prefix() {
        let code = "\"use client\";\nconst url = process.env.NEXT_PUBLIC_API_URL;";
        let v = check(code, "/src/components/Profile.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "NEXT_PUBLIC_ prefix is allowed: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_silent_without_directive() {
        let code = "const key = process.env.SECRET_API_KEY;";
        let v = check(code, "/src/lib/util.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "no use client directive: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_silent_in_api_route_even_with_use_client() {
        let code = "\"use client\";\nconst key = process.env.SECRET_API_KEY;";
        let v = check(code, "/src/app/api/users/route.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "API route never executes in browser: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_fires_in_function_call_argument() {
        let code = "\"use client\";\nlogger.debug(process.env.JWT_SECRET);";
        let v = check(code, "/src/components/Profile.tsx");
        let leaks: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
            .collect();
        assert_eq!(
            leaks.len(),
            1,
            "process.env access nested in call still leaks: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_fires_with_single_quote_directive() {
        let code = "'use client';\nconst key = process.env.SECRET_API_KEY;";
        let v = check(code, "/src/components/Profile.tsx");
        let leaks: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
            .collect();
        assert_eq!(leaks.len(), 1, "single-quoted directive must work: {v:?}");
    }

    #[test]
    fn client_env_leak_silent_with_use_server_directive() {
        let code = "\"use server\";\nconst key = process.env.SECRET_API_KEY;";
        let v = check(code, "/src/components/Form.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "use server is server-side: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_fires_for_every_violation_in_file() {
        let code = "\"use client\";\nconst a = process.env.SECRET_API_KEY;\nconst b = process.env.DATABASE_URL;";
        let v = check(code, "/src/components/Profile.tsx");
        let leaks: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
            .collect();
        assert_eq!(leaks.len(), 2, "every violation must be reported: {v:?}");
    }

    #[test]
    fn client_env_leak_silent_on_computed_access() {
        let code = "\"use client\";\nconst key = process.env[\"SECRET_API_KEY\"];";
        let v = check(code, "/src/components/Profile.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "computed access is out of scope per draft: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_silent_on_node_env() {
        let code = "\"use client\";\nif (process.env.NODE_ENV === 'production') {}";
        let v = check(code, "/src/components/Profile.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "NODE_ENV is a framework-provided public compile-time value: {v:?}"
        );
    }

    #[test]
    fn client_env_leak_silent_inside_inline_use_server_in_client_component() {
        let code = r#"
            "use client";
            async function submit() {
                "use server";
                const key = process.env.SECRET_API_KEY;
            }
        "#;
        let v = check(code, "/src/components/Profile.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
            "inline 'use server' body runs server-side, not in client bundle: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_fires_on_apikey_prop_in_get_server_side_props() {
        let code =
            "export async function getServerSideProps() { return { props: { apiKey: 'x' } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(bleeds.len(), 1, "apiKey property in props must flag: {v:?}");
        assert_eq!(bleeds[0].severity, Severity::High);
    }

    #[test]
    fn ssr_secret_bleed_fires_on_env_secret_value_in_props() {
        let code = "export async function getServerSideProps() { return { props: { x: process.env.DATABASE_TOKEN } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(
            bleeds.len(),
            1,
            "secret env value in props must flag: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_fires_in_use_server_action_return() {
        let code = "'use server';\nexport async function fetchData() { return { password: 'p', user: { name: 'x' } }; }";
        let v = check(code, "/src/app/actions.ts");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(
            bleeds.len(),
            1,
            "'use server' return with password property must flag: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_fires_on_arrow_get_server_side_props() {
        let code =
            "export const getServerSideProps = async () => { return { props: { token: 't' } }; };";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(bleeds.len(), 1, "arrow form must flag: {v:?}");
    }

    #[test]
    fn ssr_secret_bleed_fires_on_uppercase_property_name() {
        let code =
            "export async function getServerSideProps() { return { props: { API_KEY: 'x' } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(bleeds.len(), 1, "case-insensitive substring match: {v:?}");
    }

    #[test]
    fn ssr_secret_bleed_fires_on_multiple_violations_in_same_return() {
        let code = "export async function getServerSideProps() { return { props: { apiKey: 'a', dbToken: process.env.DATABASE_TOKEN } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(
            bleeds.len(),
            2,
            "every violating property must be reported: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_outside_ssr_scope() {
        let code = "function helper() { return { token: 'x' }; }";
        let v = check(code, "/src/lib/util.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "helper function with no SSR context is silent: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_safe_property_names() {
        let code = "export async function getServerSideProps() { return { props: { username: 'alice', itemCount: 3 } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "non-secret property names are silent: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_variable_referenced_return() {
        let code = "export async function getServerSideProps() { const data = { props: { apiKey: 'x' } }; return data; }";
        let v = check(code, "/pages/dashboard.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "variable-bound return is out of scope: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_spread_property() {
        let code =
            "export async function getServerSideProps() { return { props: { ...secretData } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "spread element is out of scope (separate issue): {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_in_named_function_other_than_gssp() {
        let code = "export async function getStaticProps() { return { props: { apiKey: 'x' } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "getStaticProps is not in scope for this rule: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_safe_use_server_return() {
        let code = "'use server';\nexport async function loadUser() { return { name: 'alice', age: 30 }; }";
        let v = check(code, "/src/app/actions.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "'use server' return with safe properties is silent: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_helper_function_inside_gssp() {
        let code = "export async function getServerSideProps() {\n  function buildHeaders() { return { token: 'h' }; }\n  return { props: { name: 'alice' } };\n}";
        let v = check(code, "/pages/dashboard.tsx");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "helper function return is not serialized: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_helper_function_inside_use_server_file() {
        let code = "'use server';\nexport async function loadUser() {\n  function inner() { return { password: 'p' }; }\n  return { name: 'alice' };\n}";
        let v = check(code, "/src/app/actions.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "inner helper return is not serialized: {v:?}"
        );
    }

    // Concise arrow body `() => ({ ... })` has no ReturnStatement, so the check
    // must run from `visit_arrow_function_expression` instead.
    #[test]
    fn ssr_secret_bleed_fires_on_concise_arrow_get_server_side_props() {
        let code = "export const getServerSideProps = async () => ({ props: { apiKey: 'x' } });";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(bleeds.len(), 1, "concise arrow body must flag: {v:?}");
    }

    #[test]
    fn ssr_secret_bleed_fires_on_nested_object_in_props() {
        let code = "export async function getServerSideProps() { return { props: { user: { token: process.env.JWT_SECRET } } }; }";
        let v = check(code, "/pages/dashboard.tsx");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(bleeds.len(), 1, "deeply nested secret must flag: {v:?}");
    }

    #[test]
    fn ssr_secret_bleed_fires_on_arrow_use_server_action() {
        let code = "'use server';\nexport const fetchUserSecrets = async (id) => { return { id, apiKey: process.env.STRIPE_SECRET_KEY }; };";
        let v = check(code, "/src/app/actions.ts");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(
            bleeds.len(),
            1,
            "arrow-form 'use server' action with secret env value must flag: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_fires_on_concise_arrow_use_server_action() {
        let code =
            "'use server';\nexport const loadConfig = async () => ({ apiKey: process.env.STRIPE_SECRET_KEY });";
        let v = check(code, "/src/app/actions.ts");
        let bleeds: Vec<_> = v
            .iter()
            .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
            .collect();
        assert_eq!(
            bleeds.len(),
            1,
            "concise-body arrow 'use server' action must flag: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_safe_arrow_use_server_action() {
        let code =
            "'use server';\nexport const loadUser = async (id) => { return { id, name: 'alice' }; };";
        let v = check(code, "/src/app/actions.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "arrow-form 'use server' action with safe properties is silent: {v:?}"
        );
    }

    #[test]
    fn ssr_secret_bleed_silent_on_helper_arrow_inside_use_server_arrow() {
        let code = "'use server';\nexport const loadUser = async () => {\n  const inner = () => ({ password: 'p' });\n  return { name: 'alice' };\n};";
        let v = check(code, "/src/app/actions.ts");
        assert!(
            v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
            "inner helper arrow return is not serialized to client: {v:?}"
        );
    }
}
