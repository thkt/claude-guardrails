use super::{Rule, Severity, Violation, RE_JS_FILE};
use crate::analysis::scanner::{
    build_line_offsets, build_source_masks, extract_delimited_range, offset_to_line,
};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::collections::HashSet;
use std::str;
use std::sync::LazyLock;

static RE_CONSOLE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_CONSOLE_CALL",
        r"console\.(log|warn|error|info|debug)\s*\(",
    )
});

static RE_LOGGER_CALL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_LOGGER_CALL",
        r"(logger|log)\.(log|warn|error|info|debug)\s*\(",
    )
});

static RE_SENSITIVE_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_SENSITIVE_KEYWORD",
        r"\b(password|secret|token|apiKey|api_key|credential|auth|private_key|privateKey|accessToken|access_token|refreshToken|refresh_token)\b",
    )
});

const MSG_CONSOLE: &str =
    "Logging sensitive data (password, token, secret). Remove or mask before logging.";
const MSG_LOGGER: &str = "Logging sensitive data via logger. Remove or mask before logging.";

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|content: &str, file_path: &str, _lines: &[(u32, &str)]| {
        // Skip mask/offset construction when no call site exists.
        if !RE_CONSOLE_CALL.is_match(content) && !RE_LOGGER_CALL.is_match(content) {
            return Vec::new();
        }
        let mut violations = Vec::new();
        let mut reported_lines = HashSet::new();
        let line_offsets = build_line_offsets(content);
        let masks = build_source_masks(content);
        // build_source_masks replaces hidden bytes with ASCII space and preserves
        // every original byte boundary, so the buffer is still valid UTF-8.
        let code_visible = str::from_utf8(&masks.code_visible)
            .expect("sensitive_logging: code_visible preserves UTF-8 by construction");

        let console_hits = RE_CONSOLE_CALL.find_iter(content).map(|m| (m, MSG_CONSOLE));
        let logger_hits = RE_LOGGER_CALL.find_iter(content).map(|m| (m, MSG_LOGGER));

        for (caps, msg) in console_hits.chain(logger_hits) {
            if masks.comment.get(caps.start()).copied().unwrap_or(false) {
                continue;
            }
            let Some((args_start, args_end)) =
                extract_delimited_range(content, caps.end(), b'(', b')')
            else {
                continue;
            };
            if !RE_SENSITIVE_KEYWORD.is_match(&code_visible[args_start..args_end]) {
                continue;
            }
            let line_num = offset_to_line(&line_offsets, caps.start());
            if reported_lines.insert(line_num) {
                violations.push(Violation {
                    rule: super::rule_id::SENSITIVE_LOGGING.to_owned(),
                    severity: Severity::High,
                    fix: msg.to_owned(),
                    file: file_path.to_owned(),
                    line: Some(u32::try_from(line_num).unwrap_or(u32::MAX)),
                    origin: None,
                });
            }
        }

        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Violation> {
        super::super::check_rule(&RULE, content, "/src/auth/login.ts")
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
            assert_eq!(violations.len(), 1, "Should detect: {keyword}");
        }
    }

    #[test]
    fn detects_template_literal_with_sensitive() {
        let content = r"console.log(`User ${username} password: ${password}`);";
        assert!(!check(content).is_empty());
    }

    #[test]
    fn allows_safe_logging() {
        let cases = [
            r"console.log('Password:', '***MASKED***');",
            r"console.log('User logged in:', userId);",
            r"console.log('Request received');",
        ];
        for content in cases {
            assert!(check(content).is_empty(), "Should allow: {content}");
        }
    }

    #[test]
    fn ignores_comments() {
        let content = "// console.log('Debug:', password);\nconsole.log('User:', username);";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_nested_function_call() {
        let content = r"console.log(getUser(id), password);";
        assert_eq!(check(content).len(), 1);
    }

    #[test]
    fn detects_deeply_nested_calls() {
        let content = r"console.log(getUser(getSession(token)), secret);";
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
        let content = r"console.log(password, secret);";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_sensitive_in_template_interpolation() {
        let content = r"console.log(`value: ${getPassword(password)}`);";
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

    #[test]
    fn ignores_multiline_block_comment() {
        let content = "/*\nconsole.log(password);\n*/";
        assert!(check(content).is_empty());
    }

    // T-019: NFR-001 perf < 10ms/file. 20 console/logger 呼び出しを含む典型的
    // hot path で sensitive_logging 自身の per-file 時間が ceiling 内に収まる。
    #[test]
    fn nfr001_sensitive_logging_under_10ms() {
        use std::fmt::Write as _;
        let mut content = String::new();
        for i in 0..20 {
            writeln!(content, "console.log('user', user{i});").unwrap();
            writeln!(content, "logger.info('event', {{ id: {i} }});").unwrap();
        }
        content.push_str("console.log('password', password);\n");
        content.push_str("logger.error('token', accessToken);\n");

        super::super::assert_under_10ms("sensitive-logging", 100, || {
            let _ = check(&content);
        });
    }
}
