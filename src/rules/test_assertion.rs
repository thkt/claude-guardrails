use super::{rule_id, Severity, Violation, RE_TEST_FILE};
use crate::analysis::ast;
use crate::regex_compile::regex_or_die;
use oxc_ast::ast::{CallExpression, Expression, FunctionBody, Program};
use oxc_ast_visit::{walk, Visit};
use oxc_span::{GetSpan, Span};
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

// Non-`expect` assertion forms. Their presence means the test verifies a real
// value through chai `assert.`, BDD `should.`, or a promise `.rejects`/`.resolves`
// chain, so the expect()-quality classification is suppressed for that body.
static RE_NON_EXPECT_ASSERTION: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_NON_EXPECT_ASSERTION",
        r"(assert\.|should\.|\.rejects\.|\.resolves\.)",
    )
});

// Matchers that pass for almost any defined/truthy value: they check shape, not
// the actual result. A test whose only assertions are these verifies little.
const WEAK_MATCHERS: &[&str] = &["toBeTruthy", "toBeDefined", "toBeFalsy"];

// Matchers that assert a spy was called or returned, not the value it produced.
const MOCK_MATCHERS: &[&str] = &[
    "toHaveBeenCalled",
    "toHaveBeenCalledWith",
    "toHaveBeenCalledTimes",
    "toHaveBeenLastCalledWith",
    "toHaveBeenNthCalledWith",
    "toHaveReturned",
    "toHaveReturnedWith",
    "toHaveReturnedTimes",
    "toHaveLastReturnedWith",
    "toHaveNthReturnedWith",
];

// Equality matchers whose self-comparison `expect(x).toBe(x)` always holds and so
// proves nothing.
const EQUALITY_MATCHERS: &[&str] = &["toBe", "toEqual", "toStrictEqual"];

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
        let Some((severity, fix)) = self.classify(name, body) else {
            return;
        };
        self.violations.push(Violation {
            rule: rule_id::TEST_ASSERTION.to_owned(),
            severity,
            fix,
            file: self.file_path.to_owned(),
            line: Some(ast::span_to_line(self.line_offsets, call.span)),
            origin: None,
        });
    }

    /// Grades a test body. `None` means the body verifies a real value. The
    /// zero-assertion case keeps the original Medium finding; the three quality
    /// classes (tautological / mock-only / weak) layer only onto `expect()`
    /// chains, so a strong `assert.`/`should.` body is never downgraded.
    fn classify(&self, name: &str, body: &FunctionBody) -> Option<(Severity, String)> {
        // The slice is lexical, so an assertion inside a nested `it`/`test`
        // callback also counts toward the outer test (the visitor still grades
        // the nested one on its own). Accepted: nested test definitions are
        // uncommon and the rule is advisory, so the rare false negative costs
        // less than tracking descendant spans.
        let body_src = &self.content[body.span.start as usize..body.span.end as usize];
        if !RE_ASSERTION.is_match(body_src) {
            return Some((
                Severity::Medium,
                format!("Test '{name}' has no assertions. Add expect() or assert calls."),
            ));
        }
        let mut collector = ExpectCollector {
            content: self.content,
            expects: Vec::new(),
        };
        collector.visit_function_body(body);
        let expects = collector.expects;
        // An assertion is present but resolves to no `expect()` chain (e.g. only
        // `assert.equal`): a non-expect assertion verifies a value, nothing to grade.
        if expects.is_empty() {
            return None;
        }
        let verifies_value = RE_NON_EXPECT_ASSERTION.is_match(body_src)
            || expects
                .iter()
                .any(|e| !e.is_weak && !e.is_mock && !e.is_tautological);
        if verifies_value {
            return None;
        }
        if let Some(taut) = expects.iter().find(|e| e.is_tautological) {
            return Some((
                Severity::Medium,
                format!(
                    "Test '{name}' asserts a value against itself (expect({0}).{1}({0})). Compare against an expected value.",
                    taut.target, taut.matcher
                ),
            ));
        }
        let matchers = expects
            .iter()
            .map(|e| e.matcher.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if expects.iter().all(|e| e.is_mock) {
            return Some((
                Severity::Medium,
                format!("Test '{name}' only checks mock calls ({matchers}), not the result. Assert the produced value."),
            ));
        }
        Some((
            Severity::Low,
            format!("Test '{name}' only uses weak matchers ({matchers}). Assert the actual value with toBe/toEqual."),
        ))
    }
}

impl<'a> Visit<'a> for TestAssertionVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_call(call);
        walk::walk_call_expression(self, call);
    }
}

/// One `expect(target).matcher(arg)` assertion, graded for verification quality.
struct ExpectInfo {
    target: String,
    matcher: String,
    is_weak: bool,
    is_mock: bool,
    is_tautological: bool,
}

/// Collects every `expect()` assertion in a test body, descending through nested
/// statements so a chain inside an `if`/loop is still seen.
struct ExpectCollector<'s> {
    content: &'s str,
    expects: Vec<ExpectInfo>,
}

impl<'a> Visit<'a> for ExpectCollector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(info) = analyze_expect(call, self.content) {
            self.expects.push(info);
        }
        walk::walk_call_expression(self, call);
    }
}

/// Grades the outer matcher call of an `expect()` chain. Returns None for any
/// call that is not the matcher end of such a chain (including the inner
/// `expect(target)` call itself, whose callee is the bare `expect` identifier).
fn analyze_expect(call: &CallExpression, source: &str) -> Option<ExpectInfo> {
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return None;
    };
    let matcher = member.property.name.as_str();
    let (target, negated) = find_expect_chain(&member.object, source)?;
    // A `.not` anywhere in the chain makes the assertion a deliberate, specific
    // negative check (`expect(spy).not.toHaveBeenCalled()`, `expect(x).not.toBe(x)`),
    // not a weak/mock/tautological non-verification — so no class applies.
    let is_tautological = !negated
        && EQUALITY_MATCHERS.contains(&matcher)
        && call
            .arguments
            .first()
            .and_then(|arg| arg.as_expression())
            .is_some_and(|arg| span_text(source, arg.span()).trim() == target.trim());
    Some(ExpectInfo {
        target,
        matcher: matcher.to_owned(),
        is_weak: !negated && WEAK_MATCHERS.contains(&matcher),
        is_mock: !negated && MOCK_MATCHERS.contains(&matcher),
        is_tautological,
    })
}

/// Walks the object side of a matcher call down to its `expect(...)` root,
/// returning the target argument's source text and whether the chain negates via
/// `.not` (in dot or `['not']` form). None when the chain is not rooted at `expect`.
fn find_expect_chain<'a>(expr: &'a Expression<'a>, source: &str) -> Option<(String, bool)> {
    match expr {
        Expression::CallExpression(call) => {
            if !ast::is_ident(&call.callee, "expect") {
                return None;
            }
            let arg = call.arguments.first()?.as_expression()?;
            Some((span_text(source, arg.span()).to_owned(), false))
        }
        Expression::ParenthesizedExpression(p) => find_expect_chain(&p.expression, source),
        // `.not` / `.resolves` / `['not']` — `member_name` unwraps both the dot and
        // string-literal computed forms, so negation is caught for each.
        _ => {
            let (object, name) = ast::member_name(expr)?;
            let (target, negated) = find_expect_chain(object, source)?;
            Some((target, negated || name == "not"))
        }
    }
}

fn span_text(source: &str, span: Span) -> &str {
    &source[span.start as usize..span.end as usize]
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
                expect(result).toBe(42);
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
                expect(s).toBe('{ brace }');
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_braces_in_template_literals() {
        let content = r"
            it('should handle template literal braces', () => {
                const s = `{ template ${brace} }`;
                expect(s).toContain('template');
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
                expect(1 + 1).toBe(2);
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
                expect(s).toContain('value');
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
                expect(s).toContain('a');
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
    fn ignores_member_call_not_rooted_at_test() {
        // `this.it(...)` — the callee root is `this`, not the `it`/`test`
        // identifier, so the call is not a test definition and never fires.
        let content = r"
            this.it('looks like a test', () => {
                doSomething();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_spread_argument_call_without_assertion() {
        // `it(...args, fn)` — the spread element is not an expression argument, so
        // name extraction skips it; the callback still resolves and fires.
        let content = r"
            it(...labels, () => {
                doSomething();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
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

    // --- #345: verification-quality classification of present assertions ---

    #[test]
    fn flags_weak_only_assertion_at_low() {
        // Only `toBeTruthy` — passes for any truthy value, so it verifies shape
        // not the result. Lower severity than no-assertion to keep inline noise down.
        let content = r"
            it('should produce a value', () => {
                const result = doSomething();
                expect(result).toBeTruthy();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Low);
        assert!(violations[0].fix.contains("weak matchers"));
        assert!(violations[0].fix.contains("toBeTruthy"));
    }

    #[test]
    fn flags_only_weak_matchers_across_multiple_assertions() {
        let content = r"
            it('should produce values', () => {
                expect(a()).toBeDefined();
                expect(b()).toBeFalsy();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Low);
    }

    #[test]
    fn allows_weak_matcher_alongside_strong_assertion() {
        // A strong `toBe(42)` verifies the value, so the weak one no longer matters.
        let content = r"
            it('should produce a value', () => {
                expect(defined()).toBeDefined();
                expect(compute()).toBe(42);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_weak_matcher_alongside_non_expect_assertion() {
        // chai `assert.equal` verifies the value even though the expect is weak.
        let content = r"
            it('should produce a value', () => {
                expect(result).toBeTruthy();
                assert.equal(result, 42);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn flags_mock_only_assertion_at_medium() {
        // Only `toHaveBeenCalled` — proves the spy ran, not what was produced.
        let content = r"
            it('should call the dependency', () => {
                runThing();
                expect(dep).toHaveBeenCalled();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Medium);
        assert!(violations[0].fix.contains("mock calls"));
        assert!(violations[0].fix.contains("toHaveBeenCalled"));
    }

    #[test]
    fn flags_mock_only_with_called_with_matcher() {
        let content = r"
            it('should call with args', () => {
                runThing();
                expect(dep).toHaveBeenCalledWith(1, 2);
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Medium);
        assert!(violations[0].fix.contains("mock calls"));
    }

    #[test]
    fn allows_mock_matcher_alongside_value_assertion() {
        let content = r"
            it('should call and return', () => {
                const out = runThing();
                expect(dep).toHaveBeenCalled();
                expect(out).toBe(7);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn flags_tautological_assertion_at_medium() {
        // `expect(x).toBe(x)` holds for any x, so it proves nothing.
        let content = r"
            it('should equal itself', () => {
                const x = compute();
                expect(x).toBe(x);
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Medium);
        assert!(violations[0].fix.contains("against itself"));
    }

    #[test]
    fn flags_tautological_with_member_expression_target() {
        let content = r"
            it('should equal itself', () => {
                expect(obj.value).toEqual(obj.value);
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Medium);
        assert!(violations[0].fix.contains("against itself"));
    }

    #[test]
    fn allows_non_tautological_equality() {
        // `expect(x).toBe(expected)` compares against a different value: a real check.
        let content = r"
            it('should equal the expected value', () => {
                expect(compute()).toBe(expected);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_negated_self_comparison() {
        // `expect(x).not.toBe(x)` is a contradiction, not a tautology, and toBe is
        // a real-value matcher, so the test is treated as verifying a value.
        let content = r"
            it('should differ from itself', () => {
                expect(x).not.toBe(x);
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn tautological_takes_priority_over_weak() {
        // Neither assertion verifies a value; the tautology is the more specific
        // and higher-severity classification.
        let content = r"
            it('should verify nothing', () => {
                expect(x).toBe(x);
                expect(y).toBeTruthy();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Medium);
        assert!(violations[0].fix.contains("against itself"));
    }

    #[test]
    fn allows_negated_mock_assertion() {
        // `expect(spy).not.toHaveBeenCalled()` is a deliberate non-interaction
        // check (e.g. cache hit must not reach the backend), a real verification.
        let content = r"
            it('should not call the backend on cache hit', () => {
                runCached();
                expect(backend).not.toHaveBeenCalled();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_negated_weak_assertion() {
        // `expect(x).not.toBeTruthy()` is a specific negative check, not a weak one.
        let content = r"
            it('should be falsy', () => {
                expect(compute()).not.toBeTruthy();
            });
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn flags_weak_and_mock_mix_without_value_assertion() {
        // A weak check plus a mock check still verifies no produced value; falls to
        // the weak (Low) classification since the assertions are not uniformly mock.
        let content = r"
            it('should verify nothing', () => {
                expect(value).toBeTruthy();
                expect(dep).toHaveBeenCalled();
            });
        ";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Low);
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
