use super::{Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

/// Matches console.log/warn/error/info/debug calls
static RE_CONSOLE_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"console\.(log|warn|error|info|debug)\s*\(")
        .expect("RE_CONSOLE_CALL: invalid regex")
});

/// Matches logger.log/warn/error/info/debug calls
static RE_LOGGER_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(logger|log)\.(log|warn|error|info|debug)\s*\(")
        .expect("RE_LOGGER_CALL: invalid regex")
});

/// Sensitive keyword pattern
static RE_SENSITIVE_KEYWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(password|secret|token|apiKey|api_key|credential|auth|private_key|privateKey|accessToken|access_token|refreshToken|refresh_token)\b")
        .expect("RE_SENSITIVE_KEYWORD: invalid regex")
});

/// Extract content inside parentheses, handling nested parens and string literals.
fn extract_paren_content(content: &str, start: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    let mut depth = 1;
    let mut pos = start;

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;

    while pos < bytes.len() && depth > 0 {
        let byte = bytes[pos];

        // Handle string literals
        if in_single_quote || in_double_quote || in_template {
            if byte == b'\\' && pos + 1 < bytes.len() {
                pos += 2;
                continue;
            }
            if in_single_quote && byte == b'\'' {
                in_single_quote = false;
            } else if in_double_quote && byte == b'"' {
                in_double_quote = false;
            } else if in_template && byte == b'`' {
                in_template = false;
            }
            pos += 1;
            continue;
        }

        match byte {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            b'`' => in_template = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
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

/// Check if a position is inside a single-line comment.
fn is_in_line_comment(content: &str, pos: usize) -> bool {
    // Find the start of the line containing this position
    let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_before_pos = &content[line_start..pos];
    // Check if there's a // before this position on the same line
    line_before_pos.contains("//")
}

/// Check if content contains sensitive keywords (excluding comments).
fn contains_sensitive_keyword(content: &str) -> bool {
    for line in content.lines() {
        let line = line.trim();
        // Skip single-line comments
        if line.starts_with("//") {
            continue;
        }
        // Remove inline comments before checking
        let code = if let Some(idx) = line.find("//") {
            &line[..idx]
        } else {
            line
        };
        if RE_SENSITIVE_KEYWORD.is_match(code) {
            return true;
        }
    }
    false
}

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();
            let mut reported_lines = std::collections::HashSet::new();

            // Check console.log/warn/error/info/debug calls
            for caps in RE_CONSOLE_CALL.find_iter(content) {
                // Skip if inside a comment
                if is_in_line_comment(content, caps.start()) {
                    continue;
                }
                let match_end = caps.end();
                if let Some(args) = extract_paren_content(content, match_end) {
                    if contains_sensitive_keyword(args) {
                        let line_num = content[..caps.start()].lines().count() + 1;
                        if reported_lines.insert(line_num) {
                            violations.push(Violation {
                                rule: "sensitive-logging".to_string(),
                                severity: Severity::High,
                                failure: "Logging sensitive data (password, token, secret). Remove or mask before logging.".to_string(),
                                file: file_path.to_string(),
                                line: Some(line_num as u32),
                            });
                        }
                    }
                }
            }

            // Check logger.log/warn/error/info/debug calls
            for caps in RE_LOGGER_CALL.find_iter(content) {
                // Skip if inside a comment
                if is_in_line_comment(content, caps.start()) {
                    continue;
                }
                let match_end = caps.end();
                if let Some(args) = extract_paren_content(content, match_end) {
                    if contains_sensitive_keyword(args) {
                        let line_num = content[..caps.start()].lines().count() + 1;
                        if reported_lines.insert(line_num) {
                            violations.push(Violation {
                                rule: "sensitive-logging".to_string(),
                                severity: Severity::High,
                                failure: "Logging sensitive data via logger. Remove or mask before logging.".to_string(),
                                file: file_path.to_string(),
                                line: Some(line_num as u32),
                            });
                        }
                    }
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
        // Previously a limitation - now correctly handles nested parentheses
        let content = r#"console.log(getUser(id), password);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_deeply_nested_calls() {
        let content = r#"console.log(getUser(getSession(token)), secret);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn handles_string_with_parens() {
        // Parentheses inside strings should not affect depth tracking
        let content = r#"console.log("(test)", password);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn no_duplicate_violations() {
        // Should report only once per line
        let content = r#"console.log(password, secret);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }
}
