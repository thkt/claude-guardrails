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

/// Extract brace content while properly handling string literals and comments.
/// This prevents false positives from braces inside strings like `const s = "{"`.
/// Also handles template literal interpolations (`${...}`) by tracking brace depth within them.
fn extract_brace_content(content: &str, start: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    let mut depth = 1;
    let mut pos = start;

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut template_interp_depth: Vec<i32> = Vec::new();

    while pos < bytes.len() && depth > 0 {
        let byte = bytes[pos];
        let next_byte = bytes.get(pos + 1).copied();

        if in_line_comment {
            if byte == b'\n' {
                in_line_comment = false;
            }
            pos += 1;
            continue;
        }

        if in_block_comment {
            if byte == b'*' && next_byte == Some(b'/') {
                in_block_comment = false;
                pos += 2;
                continue;
            }
            pos += 1;
            continue;
        }

        if in_template {
            if byte == b'\\' && pos + 1 < bytes.len() {
                pos += 2;
                continue;
            }
            if byte == b'$' && next_byte == Some(b'{') {
                in_template = false;
                template_interp_depth.push(1);
                pos += 2;
                continue;
            }
            if byte == b'`' {
                in_template = false;
            }
            pos += 1;
            continue;
        }

        if !template_interp_depth.is_empty() {
            if in_single_quote || in_double_quote {
                if byte == b'\\' && pos + 1 < bytes.len() {
                    pos += 2;
                    continue;
                }
                if in_single_quote && byte == b'\'' {
                    in_single_quote = false;
                } else if in_double_quote && byte == b'"' {
                    in_double_quote = false;
                }
                pos += 1;
                continue;
            }

            if byte == b'\\' && pos + 1 < bytes.len() {
                pos += 2;
                continue;
            }
            if byte == b'\'' {
                in_single_quote = true;
                pos += 1;
                continue;
            } else if byte == b'"' {
                in_double_quote = true;
                pos += 1;
                continue;
            } else if byte == b'`' {
                in_template = true;
                pos += 1;
                continue;
            } else if byte == b'{' {
                if let Some(d) = template_interp_depth.last_mut() {
                    *d += 1;
                }
            } else if byte == b'}' {
                if let Some(d) = template_interp_depth.last_mut() {
                    *d -= 1;
                    if *d == 0 {
                        template_interp_depth.pop();
                        // Return to template mode after interpolation closes
                        in_template = true;
                        pos += 1;
                        continue;
                    }
                }
            }
            pos += 1;
            continue;
        }

        if in_single_quote || in_double_quote {
            if byte == b'\\' && pos + 1 < bytes.len() {
                pos += 2;
                continue;
            }
            if in_single_quote && byte == b'\'' {
                in_single_quote = false;
            } else if in_double_quote && byte == b'"' {
                in_double_quote = false;
            }
            pos += 1;
            continue;
        }

        if byte == b'/' {
            if next_byte == Some(b'/') {
                in_line_comment = true;
                pos += 2;
                continue;
            } else if next_byte == Some(b'*') {
                in_block_comment = true;
                pos += 2;
                continue;
            }
        }

        match byte {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            b'`' => in_template = true,
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
        let content = r#"
            it('should handle single quoted braces', () => {
                const s = '{ brace }';
                expect(s).toBeDefined();
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_braces_in_template_literals() {
        let content = r#"
            it('should handle template literal braces', () => {
                const s = `{ template ${brace} }`;
                expect(s).toBeTruthy();
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn handles_braces_in_comments() {
        let content = r#"
            it('should handle comment braces', () => {
                // { this is a comment }
                /* { block comment } */
                expect(true).toBe(true);
            });
        "#;
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
        let content = r#"
            it('should handle nested interpolation', () => {
                const obj = { a: 1 };
                const s = `value: ${obj.a > 0 ? 'positive' : 'negative'}`;
                expect(s).toBeDefined();
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_missing_assertion_with_template_interpolation() {
        let content = r#"
            it('should fail without assertion', () => {
                const fn = () => { return 42; };
                const s = `result: ${fn()}`;
                console.log(s);
            });
        "#;
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
