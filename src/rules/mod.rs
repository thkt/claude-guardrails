mod architecture;
mod bundle_size;
mod crypto_weak;
mod dom_access;
mod flaky_test;
mod generated_file;
mod naming;
mod security;
mod sensitive_file;
mod sensitive_logging;
mod sync_io;
mod test_assertion;
mod test_location;
mod transaction;

use crate::config::Config;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;

pub static RE_JS_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(tsx?|jsx?)$").expect("RE_JS_FILE: invalid regex"));

/// Returns true if the line starts with a comment marker (does not detect inline comments).
/// Note: For JSDoc-style block comments, only matches `* ` (with space) or bare `*` lines
/// to avoid false positives on multiplication expressions like `x * y`.
#[inline]
fn starts_with_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with("* ")
        || trimmed == "*"
}

/// Returns an iterator over non-comment lines with their 1-based line numbers.
/// Use this when you need to perform multiple pattern matches on the same content.
#[inline]
pub(crate) fn non_comment_lines(content: &str) -> impl Iterator<Item = (u32, &str)> {
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| !starts_with_comment(line))
        .map(|(idx, line)| ((idx + 1) as u32, line))
}

pub fn find_non_comment_match(content: &str, pattern: &Regex) -> Option<u32> {
    non_comment_lines(content)
        .find(|(_, line)| pattern.is_match(line))
        .map(|(line_num, _)| line_num)
}

pub fn count_non_comment_matches(content: &str, pattern: &Regex) -> usize {
    non_comment_lines(content)
        .filter(|(_, line)| pattern.is_match(line))
        .count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub failure: String,
    pub file: String,
    pub line: Option<u32>,
}

type Checker = Box<dyn Fn(&str, &str) -> Vec<Violation> + Send + Sync>;

pub struct Rule {
    pub file_pattern: Regex,
    checker: Checker,
}

impl Rule {
    pub fn check(&self, content: &str, file_path: &str) -> Vec<Violation> {
        (self.checker)(content, file_path)
    }
}

pub fn load_rules(config: &Config) -> Vec<Rule> {
    let mut rules = Vec::new();

    if config.rules.sensitive_file {
        rules.push(sensitive_file::rule());
    }
    if config.rules.architecture {
        rules.push(architecture::rule());
    }
    if config.rules.naming {
        rules.push(naming::rule());
    }
    if config.rules.transaction {
        rules.push(transaction::rule());
    }
    if config.rules.security {
        rules.push(security::rule());
    }
    if config.rules.crypto_weak {
        rules.push(crypto_weak::rule());
    }
    if config.rules.generated_file {
        rules.push(generated_file::rule());
    }
    if config.rules.test_location {
        rules.push(test_location::rule());
    }
    if config.rules.dom_access {
        rules.push(dom_access::rule());
    }
    if config.rules.sync_io {
        rules.push(sync_io::rule());
    }
    if config.rules.bundle_size {
        rules.push(bundle_size::rule());
    }
    if config.rules.test_assertion {
        rules.push(test_assertion::rule());
    }
    if config.rules.flaky_test {
        rules.push(flaky_test::rule());
    }
    if config.rules.sensitive_logging {
        rules.push(sensitive_logging::rule());
    }

    rules
}
