use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

struct ErrorIssue {
    pattern: &'static Lazy<Regex>,
    failure: &'static str,
    severity: Severity,
}

static RE_EMPTY_CATCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"catch\s*\([^)]*\)\s*\{\s*\}").expect("RE_EMPTY_CATCH: invalid regex")
});
static RE_COMMENT_CATCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"catch\s*\([^)]*\)\s*\{\s*//.*\s*\}").expect("RE_COMMENT_CATCH: invalid regex")
});
static RE_EMPTY_PROMISE_CATCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)")
        .expect("RE_EMPTY_PROMISE_CATCH: invalid regex")
});
static RE_NULL_PROMISE_CATCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\.catch\s*\(\s*\(\s*\)\s*=>\s*null\s*\)")
        .expect("RE_NULL_PROMISE_CATCH: invalid regex")
});

static ERROR_ISSUES: Lazy<[ErrorIssue; 4]> = Lazy::new(|| [
    ErrorIssue {
        pattern: &RE_EMPTY_CATCH,
        failure: "Add error logging (console.error) or send to error tracking service",
        severity: Severity::High,
    },
    ErrorIssue {
        pattern: &RE_COMMENT_CATCH,
        failure: "Add error logging with comment explaining why it's intentionally suppressed",
        severity: Severity::Medium,
    },
    ErrorIssue {
        pattern: &RE_EMPTY_PROMISE_CATCH,
        failure: "Add error handling or comment explaining why error is ignored",
        severity: Severity::High,
    },
    ErrorIssue {
        pattern: &RE_NULL_PROMISE_CATCH,
        failure: "Use Result type pattern or return explicit error type instead of null",
        severity: Severity::Medium,
    },
]);

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for issue in ERROR_ISSUES.iter() {
                if let Some(line_num) = find_non_comment_match(content, issue.pattern) {
                    violations.push(Violation {
                        rule: "error-handling".to_string(),
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
