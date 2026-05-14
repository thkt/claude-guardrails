use crate::ast;
use crate::rules::{rule_id, Severity, Violation, RE_TEST_FILE};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentExpression, AssignmentTarget, BinaryOperator,
    BindingPattern, CallExpression, Expression, Function, LogicalExpression, LogicalOperator,
    MethodDefinition, ObjectProperty, ObjectPropertyKind, Program, RegExpLiteral,
    VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;
use oxc_syntax::scope::ScopeFlags;

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

/// crypto API sink。当該 index に `Math.random()` が渡されると Severity::High で blocking する。
struct CryptoSink {
    object_aliases: &'static [&'static str],
    method: &'static str,
    crypto_arg_indices: &'static [usize],
}

const CRYPTO_SINK_METHODS: &[CryptoSink] = &[
    CryptoSink {
        object_aliases: &["bcrypt"],
        method: "hash",
        crypto_arg_indices: &[1],
    },
    CryptoSink {
        object_aliases: &["jsonwebtoken", "jwt"],
        method: "sign",
        crypto_arg_indices: &[1],
    },
    CryptoSink {
        object_aliases: &["crypto.subtle"],
        method: "importKey",
        crypto_arg_indices: &[1],
    },
    CryptoSink {
        object_aliases: &["crypto"],
        method: "createCipheriv",
        crypto_arg_indices: &[1, 2],
    },
    CryptoSink {
        object_aliases: &["crypto"],
        method: "createHmac",
        crypto_arg_indices: &[1],
    },
];

/// Variable / function name substring (case-insensitive) が一致したら、
/// その文脈で使われる `Math.random()` を Severity::Medium で advisory する。
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

/// (object identifier alternatives, method name alternatives, fix message).
/// Each row registers an assignment-style merge sink that pollutes its target
/// when the source is untrusted (`JSON.parse(...)`).
const POLLUTION_MERGE_SINKS: &[(&[&str], &[&str], &str)] = &[
    (
        &["Object"],
        &["assign"],
        "Object.assign with JSON.parse() source can pollute prototype. Use Object.create(null) target (a plain {} still inherits __proto__).",
    ),
    (
        &["_", "lodash"],
        &["merge", "defaultsDeep"],
        "lodash merge/defaultsDeep with JSON.parse() source can pollute prototype. Use Object.create(null) target.",
    ),
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

fn is_math_random_callee(call: &CallExpression) -> bool {
    let Expression::StaticMemberExpression(sme) = &call.callee else {
        return false;
    };
    ast::is_ident(&sme.object, "Math") && sme.property.name == "random"
}

fn is_math_random_call(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = unwrap_parenthesized(expr) else {
        return false;
    };
    is_math_random_callee(call)
}

fn member_object_chain(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(sme) => {
            let inner = member_object_chain(&sme.object)?;
            Some(format!("{}.{}", inner, sme.property.name))
        }
        _ => None,
    }
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

fn expression_contains_math_random(expr: &Expression) -> bool {
    let expr = unwrap_parenthesized(expr);
    if is_math_random_call(expr) {
        return true;
    }
    match expr {
        Expression::BinaryExpression(be) => {
            expression_contains_math_random(&be.left) || expression_contains_math_random(&be.right)
        }
        Expression::CallExpression(call) => {
            let callee_has = match &call.callee {
                Expression::StaticMemberExpression(sme) => {
                    expression_contains_math_random(&sme.object)
                }
                _ => false,
            };
            callee_has
                || call.arguments.iter().any(|a| {
                    a.as_expression()
                        .is_some_and(expression_contains_math_random)
                })
        }
        Expression::StaticMemberExpression(sme) => expression_contains_math_random(&sme.object),
        _ => false,
    }
}

/// `Math.random()` を「security 文脈で危険」と判定すべき右辺式かどうか。
/// 直接の呼び出し、`Math.floor/ceil/round` ラッパー内、または除算 (`/`) の被除数として
/// 含まれる場合は true。乗算 / 加算 jitter / 三項分岐 / JSX attribute は carve-out。
fn rhs_has_insecure_math_random(expr: &Expression) -> bool {
    if is_math_random_call(expr) {
        return true;
    }
    match expr {
        Expression::CallExpression(call) => {
            let Expression::StaticMemberExpression(sme) = &call.callee else {
                return false;
            };
            if !ast::is_ident(&sme.object, "Math") {
                return false;
            }
            if !matches!(sme.property.name.as_str(), "floor" | "ceil" | "round") {
                return false;
            }
            call.arguments.iter().any(|a| {
                a.as_expression()
                    .is_some_and(expression_contains_math_random)
            })
        }
        Expression::BinaryExpression(be) if be.operator == BinaryOperator::Division => {
            expression_contains_math_random(&be.left)
        }
        _ => false,
    }
}

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    ast::with_parsed_program(content, file_path, |program, line_offsets| {
        let mut found = Vec::new();
        found.extend(check_bidi(content, file_path, line_offsets));
        found.extend(check_program(program, line_offsets, file_path));
        found
    })
    .unwrap_or_default()
}

pub fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
) -> Vec<Violation> {
    let mut visitor = SecurityVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
        is_test_file: RE_TEST_FILE.is_match(file_path),
        in_security_named_fn: false,
    };
    visitor.visit_program(program);
    visitor.violations
}

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
    in_security_named_fn: bool,
}

impl SecurityVisitor<'_> {
    fn span_to_line(&self, span: Span) -> u32 {
        ast::span_to_line(self.line_offsets, span)
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

    fn check_prototype_pollution(&mut self, expr: &AssignmentExpression) {
        if self.is_test_file {
            return;
        }
        if assignment_target_has_pollution_segment(&expr.left) {
            self.push_violation(
                rule_id::PROTOTYPE_POLLUTION,
                Severity::High,
                "Assignment via __proto__/constructor/prototype enables prototype pollution. Use Object.defineProperty or a Map.",
                expr.span,
            );
        }
    }

    fn check_assign_with_untrusted_source(&mut self, call: &CallExpression, fix: &str) {
        let Some(target) = call.arguments.first().and_then(|a| a.as_expression()) else {
            return;
        };
        if is_null_prototype_target(target) {
            return;
        }
        let has_untrusted = call
            .arguments
            .iter()
            .skip(1)
            .any(|arg| arg.as_expression().is_some_and(is_json_parse_call));
        if has_untrusted {
            self.push_violation(rule_id::PROTOTYPE_POLLUTION, Severity::High, fix, call.span);
        }
    }

    fn check_merge_pollution_sinks(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Some((obj, method)) = ast::member_name(&call.callee) else {
            return;
        };
        let Some(&(_, _, fix)) = POLLUTION_MERGE_SINKS.iter().find(|(objs, methods, _)| {
            objs.iter().any(|o| ast::is_ident(obj, o)) && methods.contains(&method)
        }) else {
            return;
        };
        self.check_assign_with_untrusted_source(call, fix);
    }

    fn check_html_assignment(&mut self, expr: &AssignmentExpression) {
        let AssignmentTarget::StaticMemberExpression(sme) = &expr.left else {
            return;
        };
        let (severity, fix) = match sme.property.name.as_str() {
            "innerHTML" => (
                Severity::High,
                "Use textContent or DOMPurify.sanitize() instead",
            ),
            "outerHTML" => (Severity::Medium, "Use DOM methods instead"),
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
            "Use createElement/appendChild instead",
            call.span,
        );
    }

    fn check_math_random_insecure(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Expression::StaticMemberExpression(method) = &call.callee else {
            return;
        };
        if method.property.name != "toString" {
            return;
        }
        let [arg] = call.arguments.as_slice() else {
            return;
        };
        let Argument::NumericLiteral(n) = arg else {
            return;
        };
        if (n.value - 36.0).abs() > f64::EPSILON {
            return;
        }
        let Expression::CallExpression(inner) = &method.object else {
            return;
        };
        if !is_math_random_callee(inner) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::High,
            "Math.random() is not cryptographically secure. Use crypto.randomBytes() for tokens/IDs.",
            call.span,
        );
    }

    fn check_math_random_crypto_sink(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Some((obj, method)) = ast::member_name(&call.callee) else {
            return;
        };
        // method 名が CRYPTO_SINK_METHODS のどれにも一致しない CallExpression が大多数なので、
        // String を生成する member_object_chain より先に method 名で zero-cost filter する。
        if !CRYPTO_SINK_METHODS.iter().any(|s| s.method == method) {
            return;
        }
        let Some(chain) = member_object_chain(obj) else {
            return;
        };
        for sink in CRYPTO_SINK_METHODS {
            if sink.method != method {
                continue;
            }
            if !sink.object_aliases.contains(&chain.as_str()) {
                continue;
            }
            for &i in sink.crypto_arg_indices {
                if let Some(expr) = call.arguments.get(i).and_then(|a| a.as_expression()) {
                    if expression_contains_math_random(expr) {
                        self.push_violation(
                            rule_id::MATH_RANDOM_INSECURE,
                            Severity::High,
                            "Math.random() is not cryptographically secure as crypto API input. Use crypto.randomBytes() or crypto.getRandomValues().",
                            call.span,
                        );
                        return;
                    }
                }
            }
        }
    }

    fn check_math_random_keyword_var(&mut self, decl: &VariableDeclarator) {
        if self.is_test_file {
            return;
        }
        let BindingPattern::BindingIdentifier(ident) = &decl.id else {
            return;
        };
        if !name_matches_security_keyword(&ident.name) {
            return;
        }
        let Some(init) = &decl.init else {
            return;
        };
        if !rhs_has_insecure_math_random(init) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random() assigned to a security-named variable. Use crypto.randomBytes() or crypto.getRandomValues() for tokens/IDs.",
            decl.span,
        );
    }

    fn check_math_random_keyword_fn(&mut self, call: &CallExpression) {
        if self.is_test_file || !self.in_security_named_fn {
            return;
        }
        if !is_math_random_callee(call) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random() inside a security-named function. Use crypto.randomBytes() or crypto.getRandomValues() for tokens/IDs.",
            call.span,
        );
    }

    fn check_math_random_to_string_other(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Expression::StaticMemberExpression(method) = &call.callee else {
            return;
        };
        match method.property.name.as_str() {
            // `toString(36)` は check_math_random_insecure が High で扱う。
            // ここでは radix 36 のみ除外し、それ以外の toString() / toFixed() を Medium に。
            "toString" => {
                if let [Argument::NumericLiteral(n)] = call.arguments.as_slice() {
                    if (n.value - 36.0).abs() <= f64::EPSILON {
                        return;
                    }
                }
            }
            "toFixed" => {}
            _ => return,
        }
        let Expression::CallExpression(inner) = &method.object else {
            return;
        };
        if !is_math_random_callee(inner) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random().toString()/toFixed() in a likely identifier context. Use crypto.randomBytes() or crypto.getRandomValues() for tokens/IDs.",
            call.span,
        );
    }
}

impl<'a> Visit<'a> for SecurityVisitor<'_> {
    fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
        self.check_html_assignment(expr);
        self.check_prototype_pollution(expr);
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
        walk::walk_call_expression(self, it);
    }

    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let prev = self.in_security_named_fn;
        if let Some(id) = &func.id {
            if name_matches_security_keyword(&id.name) {
                self.in_security_named_fn = true;
            }
        }
        walk::walk_function(self, func, flags);
        self.in_security_named_fn = prev;
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

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        self.check_math_random_keyword_var(decl);
        let prev = self.in_security_named_fn;
        if binds_security_named_function(decl) {
            self.in_security_named_fn = true;
        }
        walk::walk_variable_declarator(self, decl);
        self.in_security_named_fn = prev;
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

/// Returns true only for `Object.create(null)`. A plain `{}` is intentionally
/// rejected because it inherits `Object.prototype` and the `__proto__` setter
/// fires when the merge source carries that key.
fn is_null_prototype_target(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    let Some((obj, "create")) = ast::member_name(&call.callee) else {
        return false;
    };
    if !ast::is_ident(obj, "Object") {
        return false;
    }
    matches!(
        call.arguments.first().and_then(|a| a.as_expression()),
        Some(Expression::NullLiteral(_))
    )
}

fn is_pollution_key(s: &str) -> bool {
    matches!(s, "__proto__" | "constructor" | "prototype")
}

fn assignment_target_has_pollution_segment(target: &AssignmentTarget) -> bool {
    match target {
        AssignmentTarget::StaticMemberExpression(sme) => {
            is_pollution_key(sme.property.name.as_str())
                || expression_has_pollution_segment(&sme.object)
        }
        AssignmentTarget::ComputedMemberExpression(cme) => {
            computed_key_is_pollution(&cme.expression)
                || expression_has_pollution_segment(&cme.object)
        }
        _ => false,
    }
}

fn expression_has_pollution_segment(expr: &Expression) -> bool {
    match expr {
        Expression::StaticMemberExpression(sme) => {
            is_pollution_key(sme.property.name.as_str())
                || expression_has_pollution_segment(&sme.object)
        }
        Expression::ComputedMemberExpression(cme) => {
            computed_key_is_pollution(&cme.expression)
                || expression_has_pollution_segment(&cme.object)
        }
        _ => false,
    }
}

fn computed_key_is_pollution(expr: &Expression) -> bool {
    matches!(expr, Expression::StringLiteral(s) if is_pollution_key(s.value.as_str()))
}

fn is_json_parse_call(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    matches!(ast::member_name(&call.callee), Some((obj, "parse")) if ast::is_ident(obj, "JSON"))
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

    fn check_js(code: &str) -> Vec<Violation> {
        check(code, "/src/app.ts")
    }

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

    // T-011: math_random_insecure_to_string_36_blocked
    #[test]
    fn math_random_insecure_to_string_36_blocked() {
        let v = check_js("const t = Math.random().toString(36).substring(2);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-011: math_random_insecure_to_string_36_no_chain_blocked
    #[test]
    fn math_random_insecure_to_string_36_no_chain_blocked() {
        let v = check_js("const t = Math.random().toString(36);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    }

    // T-012: math_random_insecure_test_file_excluded
    #[test]
    fn math_random_insecure_test_file_excluded() {
        for path in [
            "/src/util.test.ts",
            "/src/util.spec.tsx",
            "/src/util.test.js",
            "/src/util.test.jsx",
            "/src/util.spec.js",
        ] {
            let v = check("const t = Math.random().toString(36);", path);
            assert_eq!(v.len(), 0, "expected 0 violations for {path}");
        }
    }

    // T-013: math_random_multiplied_allowed
    #[test]
    fn math_random_multiplied_allowed() {
        let v = check_js("const x = Math.random() * 100;");
        assert_eq!(v.len(), 0);
    }

    // T-014: math_random_react_key_allowed
    #[test]
    fn math_random_react_key_allowed() {
        let v = check("<li key={Math.random()}>x</li>", "/src/List.tsx");
        assert_eq!(v.len(), 0);
    }

    // T-015: math_random_set_timeout_jitter_allowed
    #[test]
    fn math_random_set_timeout_jitter_allowed() {
        let v = check_js("setTimeout(fn, 100 + Math.random() * 50);");
        assert_eq!(v.len(), 0);
    }

    // T-016: math_random_insecure_fail_open_on_invalid_syntax
    #[test]
    fn math_random_insecure_fail_open_on_invalid_syntax() {
        let v = check_js("function { Math.random().toString(36) !!!");
        assert_eq!(v.len(), 0);
    }

    // T-022: math_random_crypto_sink_bcrypt_hash_blocked
    #[test]
    fn math_random_crypto_sink_bcrypt_hash_blocked() {
        let v = check_js(r#"bcrypt.hash("pwd", Math.random());"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-023: math_random_crypto_sink_jwt_sign_blocked
    #[test]
    fn math_random_crypto_sink_jwt_sign_blocked() {
        let v = check_js("jsonwebtoken.sign(payload, Math.random());");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-024: math_random_crypto_sink_subtle_import_key_blocked
    #[test]
    fn math_random_crypto_sink_subtle_import_key_blocked() {
        let v =
            check_js(r#"crypto.subtle.importKey("raw", Math.random(), algo, false, ["sign"]);"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-025: math_random_crypto_sink_create_cipheriv_blocked
    #[test]
    fn math_random_crypto_sink_create_cipheriv_blocked() {
        let v = check_js(r#"crypto.createCipheriv("aes-256-cbc", Math.random(), iv);"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-025b: math_random_crypto_sink_create_hmac_blocked
    #[test]
    fn math_random_crypto_sink_create_hmac_blocked() {
        let v = check_js(r#"crypto.createHmac("sha256", Math.random());"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-026: math_random_crypto_sink_bcrypt_with_precomputed_salt_allowed
    #[test]
    fn math_random_crypto_sink_bcrypt_with_precomputed_salt_allowed() {
        let v = check_js(r#"bcrypt.hash("pwd", precomputedSalt);"#);
        assert_eq!(v.len(), 0);
    }

    // T-027: math_random_keyword_var_token_blocked
    #[test]
    fn math_random_keyword_var_token_blocked() {
        let v = check_js("const token = Math.random();");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-028: math_random_keyword_var_math_floor_wrapper_blocked
    #[test]
    fn math_random_keyword_var_math_floor_wrapper_blocked() {
        let v = check_js("const apiKey = Math.floor(Math.random() * 1000000);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-028b: math_random_keyword_var_division_wrapper_blocked
    #[test]
    fn math_random_keyword_var_division_wrapper_blocked() {
        let v = check_js("const userId = Math.random() / 1000;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-029: math_random_keyword_var_multiplication_pass_pattern_allowed
    #[test]
    fn math_random_keyword_var_multiplication_pass_pattern_allowed() {
        let v = check_js("const token = Math.random() * 100;");
        assert_eq!(v.len(), 0);
    }

    // T-030: math_random_keyword_fn_declaration_blocked
    #[test]
    fn math_random_keyword_fn_declaration_blocked() {
        let v = check_js("function generateToken() { return Math.random(); }");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-031: math_random_keyword_fn_arrow_with_parent_blocked
    #[test]
    fn math_random_keyword_fn_arrow_with_parent_blocked() {
        let v = check_js("const generateSessionId = () => Math.floor(Math.random() * 1000000);");
        assert!(
            v.iter().any(|v| v.severity == Severity::Medium),
            "expected at least one Medium violation, got: {v:?}"
        );
    }

    // T-032: math_random_keyword_fn_no_keyword_match_allowed
    #[test]
    fn math_random_keyword_fn_no_keyword_match_allowed() {
        let v = check_js("function generateAnimOffset() { return Math.random() * 360; }");
        assert_eq!(v.len(), 0);
    }

    // T-033: math_random_to_string_no_arg_blocked
    #[test]
    fn math_random_to_string_no_arg_blocked() {
        let v = check_js("const x = Math.random().toString();");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-034: math_random_to_fixed_blocked
    #[test]
    fn math_random_to_fixed_blocked() {
        let v = check_js("const x = Math.random().toFixed(8);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-035: math_random_to_string_36_remains_high
    #[test]
    fn math_random_to_string_36_remains_high() {
        let v = check_js("const x = Math.random().toString(36);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-038: math_random_crypto_sink_parenthesized_blocked
    #[test]
    fn math_random_crypto_sink_parenthesized_blocked() {
        let v = check_js(r#"bcrypt.hash("pwd", (Math.random()));"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-039: math_random_crypto_sink_wrapped_arg_blocked
    #[test]
    fn math_random_crypto_sink_wrapped_arg_blocked() {
        let v = check_js(r#"bcrypt.hash("pwd", Math.random().toString());"#);
        assert!(
            v.iter().any(|v| v.severity == Severity::High),
            "expected at least one High violation, got: {v:?}"
        );
    }

    // T-040: math_random_keyword_fn_method_definition_blocked
    #[test]
    fn math_random_keyword_fn_method_definition_blocked() {
        let v = check_js("class Auth { generateToken() { return Math.random(); } }");
        assert!(
            v.iter().any(|v| v.severity == Severity::Medium),
            "expected at least one Medium violation, got: {v:?}"
        );
    }

    // T-041: math_random_keyword_fn_object_property_blocked
    #[test]
    fn math_random_keyword_fn_object_property_blocked() {
        let v = check_js("const auth = { generateToken: () => Math.random() };");
        assert!(
            v.iter().any(|v| v.severity == Severity::Medium),
            "expected at least one Medium violation, got: {v:?}"
        );
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
        assert!(v[0].fix.contains("DOM methods"));
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

    // T-022: prototype_pollution_literal_proto_assignment_blocked
    #[test]
    fn prototype_pollution_literal_proto_assignment_blocked() {
        let v = check_js(r#"obj["__proto__"] = x;"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-023: prototype_pollution_static_proto_assignment_blocked
    #[test]
    fn prototype_pollution_static_proto_assignment_blocked() {
        let v = check_js("obj.__proto__ = x;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-024: prototype_pollution_constructor_prototype_assignment_blocked
    #[test]
    fn prototype_pollution_constructor_prototype_assignment_blocked() {
        for code in [
            r#"obj["constructor"] = x;"#,
            "obj.constructor = x;",
            r#"obj["prototype"] = x;"#,
            "obj.prototype = x;",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
        }
    }

    // T-025: prototype_pollution_variable_key_allowed (Record lookup FP suppression)
    #[test]
    fn prototype_pollution_variable_key_allowed() {
        assert!(check_js("obj[key] = x;").is_empty());
        assert!(check_js("obj[someVar] = x;").is_empty());
        assert!(check_js("styleMap[variant] = value;").is_empty());
    }

    // T-026: prototype_pollution_normal_property_allowed
    #[test]
    fn prototype_pollution_normal_property_allowed() {
        assert!(check_js("obj.knownProp = x;").is_empty());
        assert!(check_js(r#"obj["safeName"] = x;"#).is_empty());
    }

    // T-027: prototype_pollution_pollution_key_read_allowed
    #[test]
    fn prototype_pollution_pollution_key_read_allowed() {
        assert!(check_js("if (instance.constructor === Foo) {}").is_empty());
        assert!(check_js("const c = obj.constructor;").is_empty());
        assert!(check_js("const p = obj.__proto__;").is_empty());
    }

    // T-028: prototype_pollution_object_assign_json_parse_blocked
    #[test]
    fn prototype_pollution_object_assign_json_parse_blocked() {
        let v = check_js("Object.assign(target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-029: prototype_pollution_object_assign_empty_literal_target_blocked
    // `{}` still inherits Object.prototype, so the parsed payload's `__proto__`
    // setter fires. Object.create(null) is the only safe target.
    #[test]
    fn prototype_pollution_object_assign_empty_literal_target_blocked() {
        let v = check_js("Object.assign({}, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-030: prototype_pollution_object_assign_null_proto_target_allowed
    #[test]
    fn prototype_pollution_object_assign_null_proto_target_allowed() {
        assert!(check_js("Object.assign(Object.create(null), JSON.parse(input));").is_empty());
    }

    // T-031: prototype_pollution_object_assign_static_source_allowed
    #[test]
    fn prototype_pollution_object_assign_static_source_allowed() {
        assert!(check_js("Object.assign(target, { a: 1, b: 2 });").is_empty());
        assert!(check_js("Object.assign(target, source);").is_empty());
    }

    // T-032: prototype_pollution_object_assign_multi_source_blocked
    #[test]
    fn prototype_pollution_object_assign_multi_source_blocked() {
        let v = check_js("Object.assign(target, { static: 1 }, JSON.parse(x));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-033: prototype_pollution_lodash_merge_json_parse_blocked
    #[test]
    fn prototype_pollution_lodash_merge_json_parse_blocked() {
        let v = check_js("_.merge(target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-034: prototype_pollution_lodash_defaults_deep_blocked
    #[test]
    fn prototype_pollution_lodash_defaults_deep_blocked() {
        let v = check_js("_.defaultsDeep(target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-035: prototype_pollution_lodash_full_name_blocked
    #[test]
    fn prototype_pollution_lodash_full_name_blocked() {
        for code in [
            "lodash.merge(target, JSON.parse(input));",
            "lodash.defaultsDeep(target, JSON.parse(input));",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
        }
    }

    // T-036: prototype_pollution_lodash_static_source_allowed
    #[test]
    fn prototype_pollution_lodash_static_source_allowed() {
        assert!(check_js("_.merge(target, { a: 1 });").is_empty());
        assert!(check_js("_.merge(target, source);").is_empty());
    }

    // T-037: prototype_pollution_lodash_safe_target_allowed
    #[test]
    fn prototype_pollution_lodash_safe_target_allowed() {
        assert!(check_js("_.merge(Object.create(null), JSON.parse(input));").is_empty());
    }

    // T-037b: prototype_pollution_lodash_empty_literal_target_blocked
    #[test]
    fn prototype_pollution_lodash_empty_literal_target_blocked() {
        let v = check_js("_.merge({}, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-038: prototype_pollution_record_lookup_patterns_allowed
    #[test]
    fn prototype_pollution_record_lookup_patterns_allowed() {
        for code in [
            "const label = translations[locale];",
            "const color = STATUS_LABELS[order.status];",
            "const style = styleMap[variant];",
            "const item = items[0];",
            "const v = arr[idx + 1];",
            "obj[key] += 1;",
        ] {
            assert!(check_js(code).is_empty(), "false positive for: {code}");
        }
    }

    // T-039: prototype_pollution_no_call_no_assignment_allowed
    #[test]
    fn prototype_pollution_no_call_no_assignment_allowed() {
        assert!(check_js("const p = Object.assign(target, source);").is_empty());
        assert!(check_js("const merged = _.merge({}, defaults);").is_empty());
    }

    // T-040: prototype_pollution_chain_proto_polluted_blocked
    #[test]
    fn prototype_pollution_chain_proto_polluted_blocked() {
        let v = check_js("obj.__proto__.polluted = value;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-041: prototype_pollution_chain_constructor_prototype_blocked
    #[test]
    fn prototype_pollution_chain_constructor_prototype_blocked() {
        let v = check_js("obj.constructor.prototype.admin = true;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-042: prototype_pollution_chain_computed_key_blocked
    #[test]
    fn prototype_pollution_chain_computed_key_blocked() {
        let v = check_js(r#"obj["__proto__"]["polluted"] = x;"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-043: prototype_pollution_test_file_skipped
    // Test files commonly stub prototypes (e.g. `Function.prototype.bind = jest.fn()`).
    #[test]
    fn prototype_pollution_test_file_skipped() {
        for path in [
            "/src/util.test.ts",
            "/src/util.spec.tsx",
            "/src/util.test.js",
        ] {
            let v = check("Function.prototype.bind = jest.fn();", path);
            assert!(v.is_empty(), "expected 0 violations for {path}");
        }
    }

    // T-044: prototype_pollution_bracket_form_blocked
    // ast::member_name unwrap also accepts `Object["assign"]` / `JSON["parse"]` form,
    // closing a trivial bracket-string bypass.
    #[test]
    fn prototype_pollution_bracket_form_blocked() {
        let v = check_js(r#"Object["assign"](target, JSON["parse"](input));"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
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
            let _ = check(content, "/src/handler.ts");
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
