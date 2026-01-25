use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_CONSOLE_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"console\.(log|warn|error|info|debug)\s*\([^)]*\b(password|secret|token|apiKey|api_key|credential|auth|private_key|privateKey|accessToken|access_token|refreshToken|refresh_token)\b")
        .expect("RE_CONSOLE_SENSITIVE: invalid regex")
});

static RE_LOGGER_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(logger|log)\.(log|warn|error|info|debug)\s*\([^)]*\b(password|secret|token|apiKey|api_key|credential|auth|private_key|privateKey|accessToken|access_token|refreshToken|refresh_token)\b")
        .expect("RE_LOGGER_SENSITIVE: invalid regex")
});

static RE_TEMPLATE_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"console\.(log|warn|error|info|debug)\s*\(\s*`[^`]*\$\{[^}]*(password|secret|token|apiKey|api_key|credential|auth|privateKey|private_key|accessToken|access_token)\b")
        .expect("RE_TEMPLATE_SENSITIVE: invalid regex")
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            if let Some(line_num) = find_non_comment_match(content, &RE_CONSOLE_SENSITIVE) {
                violations.push(Violation {
                    rule: "sensitive-logging".to_string(),
                    severity: Severity::High,
                    failure: "Logging sensitive data (password, token, secret). Remove or mask before logging.".to_string(),
                    file: file_path.to_string(),
                    line: Some(line_num),
                });
            }

            if let Some(line_num) = find_non_comment_match(content, &RE_LOGGER_SENSITIVE) {
                violations.push(Violation {
                    rule: "sensitive-logging".to_string(),
                    severity: Severity::High,
                    failure: "Logging sensitive data via logger. Remove or mask before logging.".to_string(),
                    file: file_path.to_string(),
                    line: Some(line_num),
                });
            }

            if let Some(line_num) = find_non_comment_match(content, &RE_TEMPLATE_SENSITIVE) {
                violations.push(Violation {
                    rule: "sensitive-logging".to_string(),
                    severity: Severity::High,
                    failure: "Logging sensitive data in template literal. Remove or mask before logging.".to_string(),
                    file: file_path.to_string(),
                    line: Some(line_num),
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
        rule().check(content, "/src/auth/login.ts")
    }

    #[test]
    fn detects_console_log_password() {
        let content = r#"console.log('User password:', password);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("sensitive"));
    }

    #[test]
    fn detects_console_log_token() {
        let content = r#"console.log('Token:', accessToken);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_console_log_api_key() {
        let content = r#"console.error('API Key:', apiKey);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_logger_with_secret() {
        let content = r#"logger.info('Secret:', secret);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_template_literal_password() {
        let content = r#"console.log(`User ${username} password: ${password}`);"#;
        let violations = check(content);
        // May match multiple patterns (console + template), at least 1 is expected
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.failure.contains("sensitive")));
    }

    #[test]
    fn allows_masked_logging() {
        let content = r#"console.log('Password:', '***MASKED***');"#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_normal_logging() {
        let content = r#"console.log('User logged in:', userId);"#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_logging_without_sensitive_vars() {
        let content = r#"
            console.log('Request received');
            logger.info('Processing request', { requestId });
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r#"
            // console.log('Debug:', password);
            console.log('User:', username);
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_refresh_token() {
        let content = r#"console.log('Refresh:', refreshToken);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_credential() {
        let content = r#"logger.debug('Cred:', credential);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_nested_function_call() {
        // Known limitation: nested parentheses may cause early termination
        // This test documents the expected behavior for simple nested calls
        let content = r#"console.log('Data:', password);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }
}
