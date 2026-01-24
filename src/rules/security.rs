use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_HTML_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(jsx?|tsx?|html?)$").expect("RE_HTML_FILE: invalid regex"));

static RE_DOC_WRITE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"document\.write\s*\(").expect("RE_DOC_WRITE: invalid regex"));
static RE_INNER_HTML: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.innerHTML\s*=").expect("RE_INNER_HTML: invalid regex"));
static RE_OUTER_HTML: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.outerHTML\s*=").expect("RE_OUTER_HTML: invalid regex"));
static RE_SET_TIMEOUT_STR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"setTimeout\s*\(\s*['"`]"#).expect("RE_SET_TIMEOUT_STR: invalid regex")
});
static RE_SET_INTERVAL_STR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"setInterval\s*\(\s*['"`]"#).expect("RE_SET_INTERVAL_STR: invalid regex")
});
static RE_POST_MESSAGE_STAR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\.postMessage\s*\([^,]+,\s*['"`]\*['"`]\s*\)"#)
        .expect("RE_POST_MESSAGE_STAR: invalid regex")
});
static RE_LOCAL_STORAGE_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"localStorage\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|auth|credential)"#)
        .expect("RE_LOCAL_STORAGE_SENSITIVE: invalid regex")
});
static RE_SESSION_STORAGE_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"sessionStorage\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|auth|credential)"#)
        .expect("RE_SESSION_STORAGE_SENSITIVE: invalid regex")
});

struct SecurityIssue {
    pattern: &'static Lazy<Regex>,
    file_pattern: &'static Lazy<Regex>,
    failure: &'static str,
    severity: Severity,
}

static SECURITY_ISSUES: [SecurityIssue; 8] = [
    SecurityIssue {
        pattern: &RE_DOC_WRITE,
        file_pattern: &RE_HTML_FILE,
        failure: "Use createElement/appendChild instead",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_INNER_HTML,
        file_pattern: &RE_HTML_FILE,
        failure: "Use textContent or DOMPurify.sanitize() instead",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_SET_TIMEOUT_STR,
        file_pattern: &RE_JS_FILE,
        failure: "Use function reference: setTimeout(() => { ... }, delay)",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_SET_INTERVAL_STR,
        file_pattern: &RE_JS_FILE,
        failure: "Use function reference: setInterval(() => { ... }, delay)",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_POST_MESSAGE_STAR,
        file_pattern: &RE_JS_FILE,
        failure: "Specify exact target origin instead of '*'",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_OUTER_HTML,
        file_pattern: &RE_HTML_FILE,
        failure: "Use DOM methods instead",
        severity: Severity::Medium,
    },
    SecurityIssue {
        pattern: &RE_LOCAL_STORAGE_SENSITIVE,
        file_pattern: &RE_JS_FILE,
        failure: "Use httpOnly cookies for sensitive data",
        severity: Severity::Medium,
    },
    SecurityIssue {
        pattern: &RE_SESSION_STORAGE_SENSITIVE,
        file_pattern: &RE_JS_FILE,
        failure: "Use httpOnly cookies for sensitive data",
        severity: Severity::Medium,
    },
];

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_HTML_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for issue in SECURITY_ISSUES.iter() {
                if !issue.file_pattern.is_match(file_path) {
                    continue;
                }
                if let Some(line_num) = find_non_comment_match(content, issue.pattern) {
                    violations.push(Violation {
                        rule: "security".to_string(),
                        severity: issue.severity,
                        failure: issue.failure.to_string(),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    });
                }
            }

            violations
        }),
    }
}
