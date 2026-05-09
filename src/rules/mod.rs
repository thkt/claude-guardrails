mod architecture;
mod bundle_size;
mod crypto_weak;
mod dom_access;
mod eval;
mod flaky_test;
mod generated_file;
mod hardcoded_secrets;
mod http_resource;
mod naming;
pub(crate) mod no_use_effect;
mod open_redirect;
mod raw_html;
mod security;
mod sensitive_file;
mod sensitive_logging;
mod sync_io;
mod test_assertion;
mod test_location;
mod transaction;

use crate::config::Config;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

pub(crate) mod rule_id {
    pub const SENSITIVE_FILE: &str = "sensitive-file";
    pub const ARCHITECTURE: &str = "architecture";
    pub const NAMING_CONVENTION: &str = "naming-convention";
    pub const TRANSACTION_BOUNDARY: &str = "transaction-boundary";
    pub const SECURITY: &str = "security";
    pub const CRYPTO_WEAK: &str = "crypto-weak";
    pub const GENERATED_FILE: &str = "generated-file";
    pub const TEST_LOCATION: &str = "test-location";
    pub const DOM_ACCESS: &str = "dom-access";
    pub const SYNC_IO: &str = "sync-io";
    pub const BUNDLE_SIZE: &str = "bundle-size";
    pub const TEST_ASSERTION: &str = "test-assertion";
    pub const FLAKY_TEST: &str = "flaky-test";
    pub const SENSITIVE_LOGGING: &str = "sensitive-logging";
    pub const EVAL: &str = "eval";
    pub const HARDCODED_SECRET: &str = "hardcoded-secret";
    pub const HTTP_RESOURCE: &str = "http-resource";
    pub const RAW_HTML: &str = "raw-html";
    pub const OPEN_REDIRECT: &str = "open-redirect";
    pub const ERR_STACK_EXPOSURE: &str = "err-stack-exposure";
    pub const CHILD_PROCESS_INJECTION: &str = "child-process-injection";
    pub const NO_USE_EFFECT: &str = "no-use-effect";
    pub const NON_LITERAL_FS_PATH: &str = "non-literal-fs-path";
    pub const BIDI_CHARACTERS: &str = "bidi-characters";
    pub const UNSAFE_REGEX: &str = "unsafe-regex";
    pub const NON_LITERAL_REQUIRE: &str = "non-literal-require";
    pub const ENV_VAR_FALLBACK: &str = "env-var-fallback";
    pub const DANGEROUS_INNER_HTML: &str = "dangerous-inner-html";
}

pub static RE_JS_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(tsx?|jsx?)$").expect("RE_JS_FILE: invalid regex"));

pub static RE_TEST_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(test|spec)\.[jt]sx?$").expect("RE_TEST_FILE: invalid regex"));

pub static RE_ALL_FILES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r".").expect("RE_ALL_FILES: invalid regex"));

pub static RE_REACT_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(tsx|jsx)$").expect("RE_REACT_FILE: invalid regex"));

/// Matches `* ` (with space) or bare `*` to avoid `x * y` false positives.
fn is_line_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("* ") || trimmed == "*"
}

/// Known limitation: `/*`/`*/` inside string literals are treated as comment markers.
pub(crate) fn non_comment_lines(content: &str) -> Vec<(u32, &str)> {
    let mut result = Vec::new();
    let mut in_block = false;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if in_block {
            if let Some(pos) = trimmed.find("*/") {
                in_block = false;
                let after = trimmed[pos + 2..].trim();
                if !after.is_empty() && !is_line_comment(after) {
                    result.push((u32::try_from(idx + 1).unwrap_or(u32::MAX), line));
                }
            }
            continue;
        }
        if let Some(pos) = trimmed.find("/*") {
            let before = trimmed[..pos].trim();
            if !trimmed[pos..].contains("*/") {
                in_block = true;
                if !before.is_empty() {
                    result.push((u32::try_from(idx + 1).unwrap_or(u32::MAX), line));
                }
                continue;
            }
            // Inline block comment like `code /* comment */ code`
            if before.is_empty() && trimmed[pos..].ends_with("*/") {
                continue;
            }
        }
        if is_line_comment(line) {
            continue;
        }
        result.push((u32::try_from(idx + 1).unwrap_or(u32::MAX), line));
    }
    result
}

pub fn find_match_in_lines(lines: &[(u32, &str)], pattern: &Regex) -> Option<u32> {
    lines
        .iter()
        .find(|(_, line)| pattern.is_match(line))
        .map(|(line_num, _)| *line_num)
}

pub fn count_matches_in_lines(lines: &[(u32, &str)], pattern: &Regex) -> usize {
    lines
        .iter()
        .filter(|(_, line)| pattern.is_match(line))
        .count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn from_linter_str(s: &str) -> Self {
        match s {
            "error" => Severity::High,
            "warning" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub fix: String,
    pub file: String,
    pub line: Option<u32>,
}

type Checker = Box<dyn Fn(&str, &str, &[(u32, &str)]) -> Vec<Violation> + Send + Sync>;

pub struct Rule {
    pub file_pattern: Regex,
    checker: Checker,
}

impl Rule {
    pub fn check(&self, content: &str, file_path: &str, lines: &[(u32, &str)]) -> Vec<Violation> {
        (self.checker)(content, file_path, lines)
    }
}

macro_rules! register_rules {
    ($config:expr, $rules:expr, $( $field:ident => $module:ident ),* $(,)?) => {
        $(if $config.rules.$field { $rules.push($module::rule()); })*
    };
}

pub fn load_rules(config: &Config) -> Vec<Rule> {
    let mut rules = Vec::new();
    register_rules!(config, rules,
        sensitive_file    => sensitive_file,
        architecture      => architecture,
        naming            => naming,
        transaction       => transaction,
        security          => security,
        crypto_weak       => crypto_weak,
        generated_file    => generated_file,
        test_location     => test_location,
        dom_access        => dom_access,
        sync_io           => sync_io,
        bundle_size       => bundle_size,
        test_assertion    => test_assertion,
        flaky_test        => flaky_test,
        sensitive_logging => sensitive_logging,
        eval              => eval,
        hardcoded_secrets => hardcoded_secrets,
        http_resource     => http_resource,
        raw_html          => raw_html,
        open_redirect     => open_redirect,
    );
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_comments_filtered() {
        let content = "code\n// comment\nmore code";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (3, "more code")]);
    }

    #[test]
    fn jsdoc_star_lines_filtered() {
        let content = "code\n * jsdoc line\n *\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (4, "more")]);
    }

    #[test]
    fn block_comment_single_line() {
        let content = "code\n/* inline comment */\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (3, "more")]);
    }

    #[test]
    fn block_comment_body_without_star_prefix() {
        // Body lines without `* ` prefix must still be filtered inside block comments
        let content =
            "let x = 1;\n/*\nThis line has no star prefix\nNeither does this one\n*/\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1;"), (6, "let y = 2;")]);
    }

    #[test]
    fn block_comment_with_code_before_open() {
        let content = "let x = 1; /*\ncomment body\n*/\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1; /*"), (4, "let y = 2;")]);
    }

    #[test]
    fn block_comment_with_code_after_close() {
        let content = "/*\ncomment\n*/ let x = 1;\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(3, "*/ let x = 1;"), (4, "let y = 2;")]);
    }

    #[test]
    fn nested_style_block_comments() {
        // Nested block comments are not supported; matches first */
        let content = "code\n/* outer\n/* inner */\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (4, "more")]);
    }

    #[test]
    fn empty_content() {
        let lines: Vec<_> = non_comment_lines("");
        assert!(lines.is_empty());
    }

    #[test]
    fn no_comments() {
        let content = "let x = 1;\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1;"), (2, "let y = 2;")]);
    }

    #[test]
    fn find_match_in_lines_skips_block_comments() {
        let re = Regex::new(r"TODO").unwrap();
        let content = "/*\nTODO: fix this\n*/\nlet x = 1;";
        assert_eq!(find_match_in_lines(&non_comment_lines(content), &re), None);
    }

    #[test]
    fn count_matches_in_lines_skips_block_comments() {
        let re = Regex::new(r"unsafe").unwrap();
        let content = "/*\nunsafe block\nunsafe fn\n*/\nunsafe { real }";
        assert_eq!(count_matches_in_lines(&non_comment_lines(content), &re), 1);
    }

    #[test]
    fn severity_from_linter_str() {
        assert_eq!(Severity::from_linter_str("error"), Severity::High);
        assert_eq!(Severity::from_linter_str("warning"), Severity::Medium);
        assert_eq!(Severity::from_linter_str("info"), Severity::Low);
        assert_eq!(Severity::from_linter_str("unknown"), Severity::Low);
    }

    // --- Known limitations ---

    #[test]
    fn known_limitation_block_comment_in_string_literal() {
        let content = "let x = '/* not a comment */';\nreal code;";
        let lines: Vec<_> = non_comment_lines(content);
        // `/*` inside string opens block comment; `*/` closes it on same line.
        assert_eq!(
            lines,
            vec![(1, "let x = '/* not a comment */';"), (2, "real code;")]
        );
    }

    #[test]
    fn known_limitation_block_comment_in_string_spans_lines() {
        let content = "let x = '/*';\nreal code;\nlet y = '*/';\nmore code;";
        let lines: Vec<_> = non_comment_lines(content);
        // `/*` in string opens block; lines 2-3 treated as inside block comment.
        assert_eq!(
            lines,
            vec![
                (1, "let x = '/*';"),
                (3, "let y = '*/';"),
                (4, "more code;")
            ]
        );
    }

    #[test]
    fn inline_block_comment_with_code_on_both_sides() {
        let content = "let x = 1; /* inline */ let y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        // Code exists on both sides of inline block comment — line should be included.
        assert_eq!(lines, vec![(1, "let x = 1; /* inline */ let y = 2;")]);
    }

    // --- load_rules ---

    #[test]
    fn load_rules_default_config_loads_all() {
        let config = Config::default();
        let rules = load_rules(&config);
        assert_eq!(rules.len(), 19);
    }

    #[test]
    fn load_rules_respects_disabled_rule() {
        let all_count = load_rules(&Config::default()).len();
        let mut config = Config::default();
        config.rules.eval = false;
        config.rules.security = false;
        let rules = load_rules(&config);
        assert_eq!(rules.len(), all_count - 2);
    }
}
