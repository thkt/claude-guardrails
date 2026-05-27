use crate::ast;
#[cfg(test)]
use crate::rules::ast_fail_open_check;
use crate::rules::{rule_id, Severity, Violation, RE_API_FILE, RE_API_OR_ROUTE_FILE, RE_TEST_FILE};
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BinaryOperator,
    BindingPattern, CallExpression, Expression, Function, LogicalExpression, MethodDefinition,
    ObjectProperty, Program, RegExpLiteral, ReturnStatement, Statement, StaticMemberExpression,
    VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::Span;
use oxc_syntax::scope::ScopeFlags;

mod math_random;
mod postmessage;
mod prototype_pollution;
mod server_io;
mod ssr_env;

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
    fn fail_open_on_invalid_or_unsupported_input() {
        assert!(check_js("function { invalid syntax !!!").is_empty());
        assert!(check_js("").is_empty());
        assert!(check("body { color: red; }", "/src/styles.css").is_empty());
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
}
