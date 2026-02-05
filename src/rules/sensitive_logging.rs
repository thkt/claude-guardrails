use super::{Rule, Severity, Violation, RE_JS_FILE};
use crate::scanner::{build_line_offsets, offset_to_line, StringScanner};
use once_cell::sync::Lazy;
use regex::Regex;

// Note: Pattern covers common logging calls. Bracket notation (console["log"]) and
// optional chaining (console?.log) are intentionally not supported - these patterns
// are rare and would add complexity without significant benefit.
static RE_CONSOLE_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"console\.(log|warn|error|info|debug)\s*\(")
        .expect("RE_CONSOLE_CALL: invalid regex")
});

static RE_LOGGER_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(logger|log)\.(log|warn|error|info|debug)\s*\(")
        .expect("RE_LOGGER_CALL: invalid regex")
});

static RE_SENSITIVE_KEYWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(password|secret|token|apiKey|api_key|credential|auth|private_key|privateKey|accessToken|access_token|refreshToken|refresh_token)\b")
        .expect("RE_SENSITIVE_KEYWORD: invalid regex")
});

fn extract_paren_content(content: &str, start: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    let mut scanner = StringScanner::new(bytes, start);
    let mut depth = 1;

    while scanner.pos < bytes.len() && depth > 0 {
        let in_context = scanner.in_non_code_context();
        let byte = scanner.current();

        scanner.advance();

        if !in_context {
            match byte {
                Some(b'(') => depth += 1,
                Some(b')') => depth -= 1,
                _ => {}
            }
        }
    }

    if depth == 0 {
        Some(&content[start..scanner.pos - 1])
    } else {
        None
    }
}

fn is_in_comment(content: &str, pos: usize) -> bool {
    let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let bytes = content.as_bytes();
    let mut scanner = StringScanner::new(bytes, line_start);

    while scanner.pos < pos {
        scanner.advance();
    }

    scanner.in_block_comment || scanner.in_line_comment
}

/// Extract code portions (excluding strings and comments) for keyword matching.
/// Template interpolations (${...}) are included as code.
fn extract_code_portions(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut scanner = StringScanner::new(bytes, 0);
    let mut code = String::new();

    while scanner.pos < bytes.len() {
        let byte = scanner.current();

        let in_interpolation = !scanner.template_interp_depth.is_empty()
            && !scanner.in_single_quote
            && !scanner.in_double_quote;

        let skip = (scanner.in_single_quote
            || scanner.in_double_quote
            || scanner.in_template
            || scanner.in_block_comment
            || scanner.in_line_comment)
            && !in_interpolation;

        scanner.advance();

        if !skip {
            if let Some(b) = byte {
                if b.is_ascii() {
                    code.push(b as char);
                }
            }
        }
    }

    code
}

fn contains_sensitive_keyword(content: &str) -> bool {
    let code = extract_code_portions(content);
    RE_SENSITIVE_KEYWORD.is_match(&code)
}

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();
            let mut reported_lines = std::collections::HashSet::new();
            let line_offsets = build_line_offsets(content);

            let check_match = |caps: regex::Match,
                               violations: &mut Vec<Violation>,
                               reported_lines: &mut std::collections::HashSet<usize>,
                               msg: &str| {
                if is_in_comment(content, caps.start()) {
                    return;
                }
                if let Some(args) = extract_paren_content(content, caps.end()) {
                    if contains_sensitive_keyword(args) {
                        let line_num = offset_to_line(&line_offsets, caps.start());
                        if reported_lines.insert(line_num) {
                            violations.push(Violation {
                                rule: "sensitive-logging".to_string(),
                                severity: Severity::High,
                                failure: msg.to_string(),
                                file: file_path.to_string(),
                                line: Some(line_num as u32),
                            });
                        }
                    }
                }
            };

            for caps in RE_CONSOLE_CALL.find_iter(content) {
                check_match(
                    caps,
                    &mut violations,
                    &mut reported_lines,
                    "Logging sensitive data (password, token, secret). Remove or mask before logging.",
                );
            }

            for caps in RE_LOGGER_CALL.find_iter(content) {
                check_match(
                    caps,
                    &mut violations,
                    &mut reported_lines,
                    "Logging sensitive data via logger. Remove or mask before logging.",
                );
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
    fn detects_sensitive_keywords() {
        let cases = [
            ("console.log('User password:', password);", "password"),
            ("console.log('Token:', accessToken);", "accessToken"),
            ("console.error('API Key:', apiKey);", "apiKey"),
            ("logger.info('Secret:', secret);", "secret"),
            ("console.log('Refresh:', refreshToken);", "refreshToken"),
            ("logger.debug('Cred:', credential);", "credential"),
        ];
        for (content, keyword) in cases {
            let violations = check(content);
            assert_eq!(violations.len(), 1, "Should detect: {}", keyword);
        }
    }

    #[test]
    fn detects_template_literal_with_sensitive() {
        let content = r#"console.log(`User ${username} password: ${password}`);"#;
        assert!(!check(content).is_empty());
    }

    #[test]
    fn allows_safe_logging() {
        let cases = [
            r#"console.log('Password:', '***MASKED***');"#,
            r#"console.log('User logged in:', userId);"#,
            r#"console.log('Request received');"#,
        ];
        for content in cases {
            assert!(check(content).is_empty(), "Should allow: {}", content);
        }
    }

    #[test]
    fn ignores_comments() {
        let content = "// console.log('Debug:', password);\nconsole.log('User:', username);";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_nested_function_call() {
        let content = r#"console.log(getUser(id), password);"#;
        assert_eq!(check(content).len(), 1);
    }

    #[test]
    fn detects_deeply_nested_calls() {
        let content = r#"console.log(getUser(getSession(token)), secret);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn handles_string_with_parens() {
        let content = r#"console.log("(test)", password);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn no_duplicate_violations() {
        let content = r#"console.log(password, secret);"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_sensitive_in_template_interpolation() {
        let content = r#"console.log(`value: ${getPassword(password)}`);"#;
        assert_eq!(check(content).len(), 1);
    }

    #[test]
    fn url_in_string_not_treated_as_comment() {
        let content = r#"console.log("https://example.com", password);"#;
        assert_eq!(check(content).len(), 1);
    }

    #[test]
    fn ignores_block_comments() {
        let content = "/* console.log(password); */\nconsole.log('safe');";
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_inline_block_comment() {
        let content = "console.log(/* password */ 'masked');";
        assert!(check(content).is_empty());
    }
}
