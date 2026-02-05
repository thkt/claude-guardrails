use super::{Rule, Severity, Violation, RE_JS_FILE};
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

/// Unified string/comment scanner to eliminate DRY violation.
/// Tracks: single quotes, double quotes, template literals, block comments.
struct StringScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    in_single_quote: bool,
    in_double_quote: bool,
    in_template: bool,
    in_block_comment: bool,
    template_interp_depth: Vec<i32>,
}

impl<'a> StringScanner<'a> {
    fn new(bytes: &'a [u8], start: usize) -> Self {
        Self {
            bytes,
            pos: start,
            in_single_quote: false,
            in_double_quote: false,
            in_template: false,
            in_block_comment: false,
            template_interp_depth: Vec::new(),
        }
    }

    fn in_string_or_comment(&self) -> bool {
        self.in_single_quote
            || self.in_double_quote
            || self.in_template
            || self.in_block_comment
            || !self.template_interp_depth.is_empty()
    }

    fn current(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos + 1).copied()
    }

    /// Advance scanner, handling strings/comments. Returns true if advanced.
    fn advance(&mut self) -> bool {
        if self.pos >= self.bytes.len() {
            return false;
        }

        let byte = self.bytes[self.pos];
        let next = self.peek();

        // Block comment handling
        if self.in_block_comment {
            if byte == b'*' && next == Some(b'/') {
                self.in_block_comment = false;
                self.pos += 2;
            } else {
                self.pos += 1;
            }
            return true;
        }

        // Template interpolation content (inside ${...})
        if !self.template_interp_depth.is_empty() {
            // Handle escape in strings inside interpolation
            if (self.in_single_quote || self.in_double_quote) && byte == b'\\' {
                self.pos += 2;
                return true;
            }
            if self.in_single_quote {
                if byte == b'\'' {
                    self.in_single_quote = false;
                }
                self.pos += 1;
                return true;
            }
            if self.in_double_quote {
                if byte == b'"' {
                    self.in_double_quote = false;
                }
                self.pos += 1;
                return true;
            }
            match byte {
                b'{' => *self.template_interp_depth.last_mut().unwrap() += 1,
                b'}' => {
                    let depth = self.template_interp_depth.last_mut().unwrap();
                    *depth -= 1;
                    if *depth == 0 {
                        self.template_interp_depth.pop();
                        self.in_template = true;
                    }
                }
                b'\'' => self.in_single_quote = true,
                b'"' => self.in_double_quote = true,
                b'`' => self.in_template = true,
                _ => {}
            }
            self.pos += 1;
            return true;
        }

        // String literal handling
        if self.in_single_quote || self.in_double_quote || self.in_template {
            if byte == b'\\' {
                self.pos += 2;
                return true;
            }
            if self.in_single_quote && byte == b'\'' {
                self.in_single_quote = false;
            } else if self.in_double_quote && byte == b'"' {
                self.in_double_quote = false;
            } else if self.in_template {
                if byte == b'`' {
                    self.in_template = false;
                } else if byte == b'$' && next == Some(b'{') {
                    self.in_template = false;
                    self.template_interp_depth.push(1);
                    self.pos += 2;
                    return true;
                }
            }
            self.pos += 1;
            return true;
        }

        // Normal code - check for string/comment start
        match byte {
            b'\'' => self.in_single_quote = true,
            b'"' => self.in_double_quote = true,
            b'`' => self.in_template = true,
            b'/' if next == Some(b'*') => {
                self.in_block_comment = true;
                self.pos += 2;
                return true;
            }
            _ => {}
        }

        self.pos += 1;
        true
    }
}

fn extract_paren_content(content: &str, start: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    let mut scanner = StringScanner::new(bytes, start);
    let mut depth = 1;

    while scanner.pos < bytes.len() && depth > 0 {
        let in_context = scanner.in_string_or_comment();
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
        if !scanner.in_string_or_comment()
            && scanner.current() == Some(b'/')
            && (scanner.peek() == Some(b'/') || scanner.peek() == Some(b'*'))
        {
            return true;
        }
        scanner.advance();
    }

    scanner.in_block_comment
}

/// Extract code portions (excluding strings and comments) for keyword matching.
/// Template interpolations (${...}) are included as code.
fn extract_code_portions(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut scanner = StringScanner::new(bytes, 0);
    let mut code = String::new();

    while scanner.pos < bytes.len() {
        let byte = scanner.current();

        // Template interpolation content is code
        let in_interpolation = !scanner.template_interp_depth.is_empty()
            && !scanner.in_single_quote
            && !scanner.in_double_quote;

        // Skip if in string literal or comment (but not interpolation)
        let skip = (scanner.in_single_quote
            || scanner.in_double_quote
            || scanner.in_template
            || scanner.in_block_comment)
            && !in_interpolation;

        // Check for line comment start
        if !skip && !in_interpolation && byte == Some(b'/') && scanner.peek() == Some(b'/') {
            while scanner.pos < bytes.len() && scanner.current() != Some(b'\n') {
                scanner.pos += 1;
            }
            continue;
        }

        scanner.advance();

        if !skip {
            if let Some(b) = byte {
                code.push(b as char);
            }
        }
    }

    code
}

fn contains_sensitive_keyword(content: &str) -> bool {
    let code = extract_code_portions(content);
    RE_SENSITIVE_KEYWORD.is_match(&code)
}

/// Pre-compute line offsets for O(log n) line number lookup.
fn build_line_offsets(content: &str) -> Vec<usize> {
    content
        .char_indices()
        .filter_map(|(i, c)| if c == '\n' { Some(i) } else { None })
        .collect()
}

fn offset_to_line(offsets: &[usize], offset: usize) -> usize {
    match offsets.binary_search(&offset) {
        Ok(idx) | Err(idx) => idx + 1,
    }
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
