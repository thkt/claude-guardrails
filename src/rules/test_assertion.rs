use super::{Rule, Severity, Violation};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_TEST_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(test|spec)\.[jt]sx?$").expect("RE_TEST_FILE: invalid regex"));

static RE_TEST_START: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(it|test)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(async\s*)?\(\s*\)\s*=>\s*\{"#)
        .expect("RE_TEST_START: invalid regex")
});

static RE_ASSERTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(expect\s*\(|assert\.|should\.|\.toEqual|\.toBe|\.toHaveBeenCalled|\.rejects\.|\.resolves\.)")
        .expect("RE_ASSERTION: invalid regex")
});

fn extract_brace_content(content: &str, start: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    let mut depth = 1;
    let mut pos = start;

    while pos < bytes.len() && depth > 0 {
        match bytes[pos] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        pos += 1;
    }

    if depth == 0 {
        Some(&content[start..pos - 1])
    } else {
        None
    }
}

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_TEST_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for caps in RE_TEST_START.captures_iter(content) {
                let test_name = caps.get(2).map(|m| m.as_str()).unwrap_or("unknown");
                let match_end = caps.get(0).map(|m| m.end()).unwrap_or(0);

                let test_body = extract_brace_content(content, match_end).unwrap_or("");

                if RE_ASSERTION.is_match(test_body) {
                    continue;
                }

                let trimmed = test_body.trim();
                if trimmed.is_empty() || trimmed.starts_with("//") {
                    continue;
                }

                let test_start = caps.get(0).map(|m| m.start()).unwrap_or(0);
                let line_num = content[..test_start].lines().count() + 1;

                violations.push(Violation {
                    rule: "test-assertion".to_string(),
                    severity: Severity::Medium,
                    failure: format!(
                        "Test '{}' has no assertions. Add expect() or assert calls.",
                        test_name
                    ),
                    file: file_path.to_string(),
                    line: Some(line_num as u32),
                });
            }

            violations
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Violation> {
        let r = rule();
        if !r.file_pattern.is_match("/src/utils.test.ts") {
            return Vec::new();
        }
        r.check(content, "/src/utils.test.ts")
    }

    #[test]
    fn detects_test_without_assertion() {
        let content = r#"
            it('should do something', () => {
                const result = doSomething();
            });
        "#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("should do something"));
    }

    #[test]
    fn allows_test_with_expect() {
        let content = r#"
            it('should return true', () => {
                const result = doSomething();
                expect(result).toBe(true);
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_test_with_assert() {
        let content = r#"
            it('should return true', () => {
                const result = doSomething();
                assert.equal(result, true);
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_empty_test_placeholder() {
        let content = r#"
            it('should do something', () => {
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_async_test_with_assertion() {
        let content = r#"
            it('should fetch data', async () => {
                const result = await fetchData();
                expect(result).toBeDefined();
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_test_with_nested_braces_and_assertion() {
        let content = r#"
            it('should handle conditional', () => {
                if (condition) {
                    doSomething();
                }
                expect(result).toBe(true);
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_test_with_nested_braces_no_assertion() {
        let content = r#"
            it('should handle conditional', () => {
                if (condition) {
                    doSomething();
                }
            });
        "#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }
}
