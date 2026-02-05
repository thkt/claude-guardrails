use super::{Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

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
    let mut depth = 1;
    let mut pos = start;

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;
    // Track brace depth for template interpolations: ${...}
    let mut template_interp_depth: Vec<i32> = Vec::new();

    while pos < bytes.len() && depth > 0 {
        let byte = bytes[pos];
        let next_byte = bytes.get(pos + 1).copied();

        // Handle template interpolation content (inside ${...})
        if !template_interp_depth.is_empty() {
            match byte {
                b'{' => {
                    *template_interp_depth.last_mut().unwrap() += 1;
                }
                b'}' => {
                    let interp_depth = template_interp_depth.last_mut().unwrap();
                    *interp_depth -= 1;
                    if *interp_depth == 0 {
                        template_interp_depth.pop();
                        in_template = true; // Back to template literal
                    }
                }
                b'\'' => in_single_quote = true,
                b'"' => in_double_quote = true,
                b'`' => in_template = true,
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            pos += 1;
            continue;
        }

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
            } else if in_template {
                if byte == b'`' {
                    in_template = false;
                } else if byte == b'$' && next_byte == Some(b'{') {
                    // Enter template interpolation
                    in_template = false;
                    template_interp_depth.push(1);
                    pos += 2;
                    continue;
                }
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

fn is_in_line_comment(content: &str, pos: usize) -> bool {
    let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let bytes = content.as_bytes();
    let mut i = line_start;

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;

    while i + 1 < pos {
        let b = bytes[i];

        if in_single_quote || in_double_quote || in_template {
            if b == b'\\' && i + 1 < pos {
                i += 2;
                continue;
            }
            if in_single_quote && b == b'\'' {
                in_single_quote = false;
            } else if in_double_quote && b == b'"' {
                in_double_quote = false;
            } else if in_template && b == b'`' {
                in_template = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            b'`' => in_template = true,
            b'/' if bytes.get(i + 1) == Some(&b'/') => return true,
            _ => {}
        }

        i += 1;
    }

    false
}

/// Find the position of line comment start, ignoring "//" inside strings.
fn find_line_comment_start(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;

    while i + 1 < bytes.len() {
        let b = bytes[i];

        if in_single_quote || in_double_quote || in_template {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if in_single_quote && b == b'\'' {
                in_single_quote = false;
            } else if in_double_quote && b == b'"' {
                in_double_quote = false;
            } else if in_template && b == b'`' {
                in_template = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            b'`' => in_template = true,
            b'/' if bytes.get(i + 1) == Some(&b'/') => return Some(i),
            _ => {}
        }

        i += 1;
    }

    None
}

fn contains_sensitive_keyword(content: &str) -> bool {
    for line in content.lines() {
        let line = line.trim();
        let code = find_line_comment_start(line)
            .map(|idx| &line[..idx])
            .unwrap_or(line);
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

            for caps in RE_CONSOLE_CALL.find_iter(content) {
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

            for caps in RE_LOGGER_CALL.find_iter(content) {
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

    #[test]
    fn detects_sensitive_in_template_interpolation() {
        // Function calls inside ${...} should be parsed correctly
        let content = r#"console.log(`value: ${getPassword(password)}`);"#;
        assert_eq!(check(content).len(), 1);
    }

    #[test]
    fn url_in_string_not_treated_as_comment() {
        // URL contains "//" but should not be treated as line comment
        let content = r#"console.log("https://example.com", password);"#;
        assert_eq!(check(content).len(), 1);
    }
}
