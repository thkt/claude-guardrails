use super::{rule_id, Rule, Severity, Violation, RE_ALL_FILES, RE_JS_FILE, RE_REACT_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_SET_TIMEOUT_STR: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_SET_TIMEOUT_STR", r#"setTimeout\s*\(\s*['"`]"#));
static RE_SET_INTERVAL_STR: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_SET_INTERVAL_STR", r#"setInterval\s*\(\s*['"`]"#));
static RE_POST_MESSAGE_STAR: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_POST_MESSAGE_STAR",
        r#"\.postMessage\s*\([^,]+,\s*['"`]\*['"`]\s*\)"#,
    )
});
static RE_LOCAL_STORAGE_SENSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_LOCAL_STORAGE_SENSITIVE",
        r#"localStorage\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|auth|credential)"#,
    )
});
static RE_SESSION_STORAGE_SENSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_SESSION_STORAGE_SENSITIVE",
        r#"sessionStorage\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|auth|credential)"#,
    )
});
static RE_DANGEROUS_INNER_HTML: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_DANGEROUS_INNER_HTML",
        r"dangerouslySetInnerHTML\s*=\s*\{",
    )
});

struct SecurityIssue {
    pattern: &'static LazyLock<Regex>,
    file_pattern: &'static LazyLock<Regex>,
    rule_id: &'static str,
    fix: &'static str,
    severity: Severity,
}

static SECURITY_ISSUES: [SecurityIssue; 6] = [
    SecurityIssue {
        pattern: &RE_SET_TIMEOUT_STR,
        file_pattern: &RE_JS_FILE,
        rule_id: rule_id::SECURITY,
        fix: "Use function reference: setTimeout(() => { ... }, delay)",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_SET_INTERVAL_STR,
        file_pattern: &RE_JS_FILE,
        rule_id: rule_id::SECURITY,
        fix: "Use function reference: setInterval(() => { ... }, delay)",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_POST_MESSAGE_STAR,
        file_pattern: &RE_JS_FILE,
        rule_id: rule_id::SECURITY,
        fix: "Specify exact target origin instead of '*'",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_LOCAL_STORAGE_SENSITIVE,
        file_pattern: &RE_JS_FILE,
        rule_id: rule_id::SECURITY,
        fix: "Use httpOnly cookies for sensitive data",
        severity: Severity::Medium,
    },
    SecurityIssue {
        pattern: &RE_SESSION_STORAGE_SENSITIVE,
        file_pattern: &RE_JS_FILE,
        rule_id: rule_id::SECURITY,
        fix: "Use httpOnly cookies for sensitive data",
        severity: Severity::Medium,
    },
    SecurityIssue {
        pattern: &RE_DANGEROUS_INNER_HTML,
        file_pattern: &RE_REACT_FILE,
        rule_id: rule_id::DANGEROUS_INNER_HTML,
        fix: "Sanitize with DOMPurify.sanitize() before assigning to dangerouslySetInnerHTML",
        severity: Severity::High,
    },
];

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_ALL_FILES.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for issue in &SECURITY_ISSUES {
            if !issue.file_pattern.is_match(file_path) {
                continue;
            }
            for &(line_num, line) in lines {
                if issue.pattern.is_match(line) {
                    violations.push(Violation {
                        rule: issue.rule_id.to_owned(),
                        severity: issue.severity,
                        fix: issue.fix.to_owned(),
                        file: file_path.to_owned(),
                        line: Some(line_num),
                    });
                }
            }
        }

        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        super::super::check_rule(&RULE, content, path)
    }

    #[test]
    fn detects_code_injection() {
        let cases = ["setTimeout('alert(1)', 100);", "setInterval('fn()', 1000);"];
        for content in cases {
            assert_eq!(check(content, "/src/utils.ts").len(), 1);
        }
    }

    #[test]
    fn detects_insecure_postmessage() {
        let content = r"window.postMessage(data, '*');";
        assert_eq!(check(content, "/src/messenger.ts").len(), 1);
    }

    #[test]
    fn detects_sensitive_storage() {
        let cases = [
            "localStorage.setItem('token', jwt);",
            "sessionStorage.setItem('password', p);",
        ];
        for content in cases {
            assert_eq!(check(content, "/src/auth.ts").len(), 1);
        }
    }

    #[test]
    fn allows_safe_patterns() {
        let cases = [
            ("setTimeout(() => fn(), 100);", "/src/utils.ts"),
            ("localStorage.setItem('theme', 'dark');", "/src/utils.ts"),
        ];
        for (content, path) in cases {
            assert!(check(content, path).is_empty());
        }
    }

    // T-007/T-008: detects_dangerously_set_inner_html_in_tsx_and_jsx
    #[test]
    fn detects_dangerously_set_inner_html_in_tsx_and_jsx() {
        for (content, path) in [
            (
                r"<div dangerouslySetInnerHTML={{ __html: x }} />",
                "/src/Component.tsx",
            ),
            (
                r"<Component dangerouslySetInnerHTML={{ __html: y }} />",
                "/src/Component.jsx",
            ),
        ] {
            let v = check(content, path);
            assert_eq!(v.len(), 1, "failed for: {path}");
            assert_eq!(
                v[0].rule,
                super::super::rule_id::DANGEROUS_INNER_HTML,
                "failed for: {path}"
            );
            assert_eq!(v[0].severity, Severity::High, "failed for: {path}");
        }
    }

    // T-009: allows_dangerously_set_inner_html_in_ts_string
    #[test]
    fn allows_dangerously_set_inner_html_in_ts_string() {
        let content = r#"const s = "dangerouslySetInnerHTML={x}";"#;
        let v = check(content, "/src/text.ts");
        assert!(
            v.is_empty(),
            "expected 0 violations in .ts file, got {}",
            v.len()
        );
    }

    // T-007: detects_dangerously_set_inner_html_with_whitespace
    #[test]
    fn detects_dangerously_set_inner_html_with_whitespace() {
        let content = r"<div dangerouslySetInnerHTML = { dangerousObject } />";
        let v = check(content, "/src/Component.tsx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, super::super::rule_id::DANGEROUS_INNER_HTML);
    }
}
