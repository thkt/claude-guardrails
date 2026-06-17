use super::{rule_id, Severity, Violation, RE_TEST_FILE};
use crate::analysis::ast;
use crate::regex_compile::regex_or_die;
use oxc_ast::ast::{CallExpression, Expression, FunctionBody, Program};
use oxc_ast_visit::{walk, Visit};
use regex::Regex;
use std::sync::LazyLock;

// Assertion signatures, matched against the callback body's source text. Scoping
// to the body (not the whole `it(...)` call) keeps a test name like
// `it('calls expect()', ...)` from masking a body that asserts nothing.
static RE_ASSERTION: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_ASSERTION",
        r"(expect\s*\(|assert\.|should\.|\.toEqual|\.toBe|\.toHaveBeenCalled|\.rejects\.|\.resolves\.)",
    )
});

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    super::ast_test_check(content, file_path, |program, line_offsets| {
        check_program(program, line_offsets, file_path, content)
    })
}

#[cfg(test)]
fn check_fail_open(content: &str, file_path: &str) -> Vec<Violation> {
    super::ast_fail_open_check(content, file_path, |program, line_offsets| {
        check_program(program, line_offsets, file_path, content)
    })
}

/// Flags `it(...)` / `test(...)` calls whose callback body contains no assertion.
/// AST traversal makes detection independent of the callee form (`it`, `it.only`,
/// `it.each(...)`) and the callback form (arrow or `function`, with or without
/// args), which the prior regex — fixed to a bare `() =>` arrow — silently missed.
pub fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
    content: &str,
) -> Vec<Violation> {
    if !RE_TEST_FILE.is_match(file_path) {
        return Vec::new();
    }
    let mut visitor = TestAssertionVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
        content,
    };
    visitor.visit_program(program);
    visitor.violations
}

struct TestAssertionVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
    content: &'s str,
}

impl TestAssertionVisitor<'_> {
    fn check_call(&mut self, call: &CallExpression) {
        if !callee_root_is_test(&call.callee) {
            return;
        }
        let Some((name, body)) = extract_test(call) else {
            return;
        };
        // An empty or comment-only body has no statements: an intentional
        // placeholder, not a missing assertion.
        if body.statements.is_empty() {
            return;
        }
        // The slice is lexical, so an assertion inside a nested `it`/`test`
        // callback also satisfies the outer test (the visitor still flags the
        // nested one on its own). Accepted: nested test definitions are
        // uncommon and the rule is advisory, so the rare false negative costs
        // less than tracking descendant spans.
        let body_src = &self.content[body.span.start as usize..body.span.end as usize];
        if RE_ASSERTION.is_match(body_src) {
            return;
        }
        self.violations.push(Violation {
            rule: rule_id::TEST_ASSERTION.to_owned(),
            severity: Severity::Medium,
            fix: format!("Test '{name}' has no assertions. Add expect() or assert calls."),
            file: self.file_path.to_owned(),
            line: Some(ast::span_to_line(self.line_offsets, call.span)),
            origin: None,
        });
    }
}

impl<'a> Visit<'a> for TestAssertionVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_call(call);
        walk::walk_call_expression(self, call);
    }
}

/// True when the leftmost identifier of the callee chain is `it` or `test`.
/// Unwraps member access (`it.only`, `it.skip`) and the call that `it.each(table)`
/// produces before invoking the test, so every common modifier resolves to the
/// same root.
fn callee_root_is_test(callee: &Expression) -> bool {
    match callee {
        Expression::Identifier(id) => matches!(id.name.as_str(), "it" | "test"),
        Expression::StaticMemberExpression(m) => callee_root_is_test(&m.object),
        Expression::ComputedMemberExpression(m) => callee_root_is_test(&m.object),
        Expression::CallExpression(c) => callee_root_is_test(&c.callee),
        Expression::ParenthesizedExpression(p) => callee_root_is_test(&p.expression),
        _ => false,
    }
}

/// Pulls the test name (first string-literal arg) and the callback body (first
/// arrow- or function-expression arg) out of a test call. Returns None when no
/// callback is present (e.g. `it.todo('pending')`), so name-only calls never fire.
fn extract_test<'b>(call: &'b CallExpression<'b>) -> Option<(&'b str, &'b FunctionBody<'b>)> {
    let mut name = "unknown";
    let mut body: Option<&FunctionBody> = None;
    for arg in &call.arguments {
        let Some(expr) = arg.as_expression() else {
            continue;
        };
        match expr {
            Expression::StringLiteral(s) if name == "unknown" => name = s.value.as_str(),
            Expression::ArrowFunctionExpression(a) if body.is_none() => body = Some(&a.body),
            Expression::FunctionExpression(f) if body.is_none() => body = f.body.as_deref(),
            _ => {}
        }
    }
    Some((name, body?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Violation> {
        super::check(content, "/src/utils.test.ts")
    }

    #[test]
    fn detects_test_without_assertion() {
        let content = r"
            it('should do something', () => {
                const result = doSomething();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("should do something"));
    }

    #[test]
    fn allows_test_with_expect() {
        let content = r"
            it('should return true', () => {
                const result = doSomething();
                expect(result).toBe(true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_test_with_assert() {
        let content = r"
            it('should return true', () => {
                const result = doSomething();
                assert.equal(result, true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_empty_test_placeholder() {
        let content = r"
            it('should do something', () => {
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_async_test_with_assertion() {
        let content = r"
            it('should fetch data', async () => {
                const result = await fetchData();
                expect(result).toBeDefined();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_test_with_nested_braces_and_assertion() {
        let content = r"
            it('should handle conditional', () => {
                if (condition) {
                    doSomething();
                }
                expect(result).toBe(true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_test_with_nested_braces_no_assertion() {
        let content = r"
            it('should handle conditional', () => {
                if (condition) {
                    doSomething();
                }
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn handles_braces_in_string_literals() {
        let content = r#"
            it('should handle string with braces', () => {
                const s = "{ not a real brace }";
                expect(s).toBe("{ not a real brace }");
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_braces_in_single_quotes() {
        let content = r"
            it('should handle single quoted braces', () => {
                const s = '{ brace }';
                expect(s).toBeDefined();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_braces_in_template_literals() {
        let content = r"
            it('should handle template literal braces', () => {
                const s = `{ template ${brace} }`;
                expect(s).toBeTruthy();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_braces_in_comments() {
        let content = r"
            it('should handle comment braces', () => {
                // { this is a comment }
                /* { block comment } */
                expect(true).toBe(true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_missing_assertion_with_string_braces() {
        let content = r#"
            it('should fail without assertion', () => {
                const s = "{ fake brace }";
                console.log(s);
            });
        "#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn handles_template_literal_interpolation_with_braces() {
        let content = r#"
            it('should handle interpolation with arrow function', () => {
                const fn = () => { return 42; };
                const s = `result: ${fn()}`;
                expect(s).toBe("result: 42");
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_nested_template_interpolation() {
        let content = r"
            it('should handle nested interpolation', () => {
                const obj = { a: 1 };
                const s = `value: ${obj.a > 0 ? 'positive' : 'negative'}`;
                expect(s).toBeDefined();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_missing_assertion_with_template_interpolation() {
        let content = r"
            it('should fail without assertion', () => {
                const fn = () => { return 42; };
                const s = `result: ${fn()}`;
                console.log(s);
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn handles_string_inside_interpolation() {
        let content = r#"
            it('should handle string with braces inside interpolation', () => {
                const s = `value: ${"a{b}c"}`;
                expect(s).toBeDefined();
            });
        "#;
        assert!(check(content).is_empty());
    }

    // --- #344 regression: notations the bare-`() =>` regex could not reach ---

    #[test]
    fn detects_it_only_without_assertion() {
        // `it.only(...)` — callee is a member expression, so `(it|test)\s*\(` never
        // matched and the missing assertion slipped through.
        let content = r"
            it.only('should focus this', () => {
                const result = doSomething();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("should focus this"));
    }

    #[test]
    fn allows_it_only_with_assertion() {
        let content = r"
            it.only('should focus this', () => {
                expect(doSomething()).toBe(true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_function_callback_without_assertion() {
        // `function () {}` callback (Mocha/Jest standard) — the regex required an
        // arrow, so this whole notation was invisible.
        let content = r"
            it('should work', function () {
                const result = doSomething();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("should work"));
    }

    #[test]
    fn allows_function_callback_with_assertion() {
        let content = r"
            it('should work', function () {
                expect(doSomething()).toBe(true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_arg_bearing_arrow_without_assertion() {
        // `(ctx) =>` / `(done) =>` — the regex demanded empty parens `(\s*)`, so any
        // callback parameter (Vitest test context, Jest done) defeated it.
        let content = r"
            it('should receive context', (ctx) => {
                const result = doSomething(ctx);
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("should receive context"));
    }

    #[test]
    fn allows_arg_bearing_arrow_with_assertion() {
        let content = r"
            it('should receive context', (ctx) => {
                expect(doSomething(ctx)).toBe(true);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_test_each_without_assertion() {
        // `it.each(table)('name', fn)` — the callee is the call `it.each(table)`,
        // reached by unwrapping the inner call to its `it` root.
        let content = r"
            it.each([1, 2, 3])('handles %s', (n) => {
                const result = doSomething(n);
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("handles %s"));
    }

    #[test]
    fn detects_computed_member_callee_without_assertion() {
        // `it['only'](...)` — computed member callee, unwrapped to its `it` root.
        let content = r"
            it['only']('computed focus', () => {
                const result = doSomething();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("computed focus"));
    }

    #[test]
    fn detects_parenthesized_callee_without_assertion() {
        // `(it)(...)` — parenthesized callee, unwrapped to its `it` root.
        let content = r"
            (it)('parenthesized', () => {
                const result = doSomething();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("parenthesized"));
    }

    #[test]
    fn ignores_describe_block_without_assertion() {
        // A `describe` body legitimately holds no assertion; only `it`/`test` fire.
        let content = r"
            describe('a group', () => {
                const shared = setup();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_non_test_file() {
        // Self-gates on RE_TEST_FILE: production code outside *.test/*.spec is skipped.
        let content = r"
            it('not a test file', () => {
                doSomething();
            });
        ";
        assert!(check_fail_open(content, "/src/utils.ts").is_empty());
    }

    #[test]
    fn fail_open_on_invalid_syntax() {
        assert!(check_fail_open("function { invalid !!!", "/src/utils.test.ts").is_empty());
    }

    #[test]
    fn nfr001_test_assertion_under_10ms() {
        let content = concat!(
            "it('a', () => { const x = f(); });\n",
            "it.only('b', () => { expect(f()).toBe(1); });\n",
            "it('c', function () { g(); });\n",
            "it('d', (ctx) => { expect(ctx).toBeDefined(); });\n",
            "it.each([1, 2])('e %s', (n) => { h(n); });\n",
            "test('f', async () => { await j(); });\n",
        );
        super::super::assert_under_10ms("test_assertion", 100, || {
            let _ = super::check(content, "/src/utils.test.ts");
        });
    }
}
