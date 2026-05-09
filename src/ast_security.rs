use crate::ast;
use crate::rules::{rule_id, Severity, Violation, RE_TEST_FILE};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, BinaryOperator, CallExpression, Expression,
    LogicalExpression, LogicalOperator, ObjectPropertyKind, Program, RegExpLiteral,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

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
fn is_bidi_char(ch: char) -> bool {
    matches!(ch, '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
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
        if !is_ident(obj, "fs") {
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
        let Expression::StaticMemberExpression(rand) = &inner.callee else {
            return;
        };
        if !is_ident(&rand.object, "Math") || rand.property.name != "random" {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random() is not cryptographically secure. Use crypto.randomBytes() for tokens/IDs.",
            call.span,
        );
    }
}

impl<'a> Visit<'a> for SecurityVisitor<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_err_stack(it);
        self.check_child_process(it);
        self.check_fs_path(it);
        self.check_non_literal_require(it);
        self.check_math_random_insecure(it);
        walk::walk_call_expression(self, it);
    }

    fn visit_reg_exp_literal(&mut self, re: &RegExpLiteral<'a>) {
        self.check_unsafe_regex(re);
        walk::walk_reg_exp_literal(self, re);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.check_env_var_fallback(it);
        walk::walk_logical_expression(self, it);
    }
}

fn process_env_access_name<'a>(expr: &'a Expression) -> Option<&'a str> {
    let Expression::StaticMemberExpression(outer) = expr else {
        return None;
    };
    let Expression::StaticMemberExpression(inner) = &outer.object else {
        return None;
    };
    if !is_ident(&inner.object, "process") || inner.property.name != "env" {
        return None;
    }
    Some(outer.property.name.as_str())
}

fn is_ident(expr: &Expression, name: &str) -> bool {
    matches!(expr, Expression::Identifier(id) if id.name == name)
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
    if is_ident(object, "res") || is_ident(object, "response") {
        return true;
    }
    let Expression::CallExpression(inner) = object else {
        return false;
    };
    let Expression::StaticMemberExpression(inner_sme) = &inner.callee else {
        return false;
    };
    inner_sme.property.name == "status"
        && (is_ident(&inner_sme.object, "res") || is_ident(&inner_sme.object, "response"))
}

fn arg_contains_stack(arg: &Argument) -> bool {
    match arg {
        Argument::SpreadElement(s) => expr_contains_stack(&s.argument),
        _ => arg.as_expression().is_some_and(|e| expr_contains_stack(e)),
    }
}

fn expr_contains_stack(expr: &Expression) -> bool {
    match expr {
        Expression::StaticMemberExpression(sme) => {
            sme.property.name == "stack" || expr_contains_stack(&sme.object)
        }
        Expression::ObjectExpression(obj) => obj.properties.iter().any(|p| match p {
            ObjectPropertyKind::ObjectProperty(op) => expr_contains_stack(&op.value),
            ObjectPropertyKind::SpreadProperty(sp) => expr_contains_stack(&sp.argument),
        }),
        Expression::CallExpression(call) => call.arguments.iter().any(|a| arg_contains_stack(a)),
        Expression::ConditionalExpression(ce) => {
            expr_contains_stack(&ce.consequent) || expr_contains_stack(&ce.alternate)
        }
        Expression::LogicalExpression(le) => {
            expr_contains_stack(&le.left) || expr_contains_stack(&le.right)
        }
        Expression::ArrayExpression(arr) => arr.elements.iter().any(|el| match el {
            ArrayExpressionElement::SpreadElement(s) => expr_contains_stack(&s.argument),
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
        _ => arg.as_expression().is_some_and(is_static_template_literal),
    }
}

fn is_safe_path_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg.as_expression().is_some_and(is_static_path),
    }
}

fn is_static_template_literal(expr: &Expression) -> bool {
    matches!(expr, Expression::TemplateLiteral(tl) if tl.expressions.is_empty())
}

fn is_static_path(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) => true,
        _ if is_static_template_literal(expr) => true,
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
        assert!(check_js("res.json({ ...err });").is_empty());
        assert!(check_js("fileSystem.readFile(userInput, cb);").is_empty());
        assert!(check_js("require('fs').readFile(userInput, cb);").is_empty());
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
        assert_eq!(v[0].severity, Severity::Medium);
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
