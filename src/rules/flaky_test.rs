use super::{find_non_comment_match, Rule, Severity, Violation, RE_TEST_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

struct FlakyPattern {
    pattern: &'static Lazy<Regex>,
    name: &'static str,
    reason: &'static str,
}

static RE_SET_TIMEOUT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"setTimeout\s*\(").expect("RE_SET_TIMEOUT: invalid regex"));

static RE_SLEEP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(sleep|delay|wait)\s*\(\s*\d").expect("RE_SLEEP: invalid regex"));

static RE_RANDOM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Math\.random\s*\(").expect("RE_RANDOM: invalid regex"));

static RE_DATE_NOW: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Date\.now\s*\(\s*\)").expect("RE_DATE_NOW: invalid regex"));

static RE_NEW_DATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"new\s+Date\s*\(\s*\)").expect("RE_NEW_DATE: invalid regex"));

static FLAKY_PATTERNS: Lazy<[FlakyPattern; 5]> = Lazy::new(|| {
    [
        FlakyPattern {
            pattern: &RE_SET_TIMEOUT,
            name: "setTimeout",
            reason: "Use fake timers (jest.useFakeTimers) instead of real timeouts",
        },
        FlakyPattern {
            pattern: &RE_SLEEP,
            name: "sleep/delay",
            reason: "Use fake timers or waitFor instead of arbitrary delays",
        },
        FlakyPattern {
            pattern: &RE_RANDOM,
            name: "Math.random",
            reason: "Mock Math.random for deterministic tests",
        },
        FlakyPattern {
            pattern: &RE_DATE_NOW,
            name: "Date.now",
            reason: "Mock Date.now or use fake timers for time-dependent tests",
        },
        FlakyPattern {
            pattern: &RE_NEW_DATE,
            name: "new Date()",
            reason: "Mock Date or pass date as parameter for deterministic tests",
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_TEST_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for pattern in FLAKY_PATTERNS.iter() {
                if let Some(line_num) = find_non_comment_match(content, pattern.pattern) {
                    violations.push(Violation {
                        rule: "flaky-test".to_string(),
                        severity: Severity::Low,
                        failure: format!(
                            "{} can cause flaky tests. {}",
                            pattern.name, pattern.reason
                        ),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    });
                }
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
    fn detects_flaky_patterns() {
        let cases = [
            ("setTimeout(() => done(), 1000);", "setTimeout"),
            ("await sleep(500);", "sleep"),
            ("const value = Math.random();", "Math.random"),
            ("const now = Date.now();", "Date.now"),
            ("const date = new Date();", "new Date"),
        ];
        for (code, expected) in cases {
            let content = format!("it('test', () => {{ {} }});", code);
            let violations = check(&content);
            assert_eq!(violations.len(), 1, "Should detect: {}", expected);
            assert!(violations[0].failure.contains(expected));
        }
    }

    #[test]
    fn allows_fake_timers_usage() {
        let content = r#"
            beforeEach(() => {
                jest.useFakeTimers();
            });
            it('should advance time', () => {
                jest.advanceTimersByTime(1000);
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_waitfor_pattern() {
        let content = r#"
            it('should wait for element', async () => {
                await waitFor(() => expect(element).toBeVisible());
            });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_non_test_files() {
        let r = rule();
        assert!(!r.file_pattern.is_match("/src/utils.ts"));
    }

    #[test]
    fn ignores_comments() {
        let content = r#"
            // Don't use setTimeout(() => done(), 1000);
            it('should work', () => {
                expect(true).toBe(true);
            });
        "#;
        assert!(check(content).is_empty());
    }
}
