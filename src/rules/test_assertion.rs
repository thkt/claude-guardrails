use super::{Rule, Severity, Violation, RE_TEST_FILE};
use crate::analysis::scanner::{build_line_offsets, extract_delimited_content, offset_to_line};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_TEST_START: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_TEST_START",
        r#"(it|test)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(async\s*)?\(\s*\)\s*=>\s*\{"#,
    )
});

static RE_ASSERTION: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_ASSERTION",
        r"(expect\s*\(|assert\.|should\.|\.toEqual|\.toBe|\.toHaveBeenCalled|\.rejects\.|\.resolves\.)",
    )
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_TEST_FILE.clone(),
    checker: Box::new(|content: &str, file_path: &str, _lines: &[(u32, &str)]| {
        let mut violations = Vec::new();
        let line_offsets = build_line_offsets(content);

        for caps in RE_TEST_START.captures_iter(content) {
            let test_name = caps.get(2).map_or("unknown", |m| m.as_str());
            let match_end = caps.get(0).map_or(0, |m| m.end());

            let test_body = extract_delimited_content(content, match_end, b'{', b'}').unwrap_or("");

            if RE_ASSERTION.is_match(test_body) {
                continue;
            }

            let trimmed = test_body.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            let test_start = caps.get(0).map_or(0, |m| m.start());
            let line_num = offset_to_line(&line_offsets, test_start);

            violations.push(Violation {
                rule: super::rule_id::TEST_ASSERTION.to_owned(),
                severity: Severity::Medium,
                fix: format!("Test '{test_name}' has no assertions. Add expect() or assert calls."),
                file: file_path.to_owned(),
                line: Some(u32::try_from(line_num).unwrap_or(u32::MAX)),
                origin: None,
            });
        }

        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Violation> {
        super::super::check_rule(&RULE, content, "/src/utils.test.ts")
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
}
