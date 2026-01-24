use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_EXCLUDED_FILE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\.(test|spec)\.[jt]sx?$|/__tests__/|/test/|\.stories\.[jt]sx?$|\.config\.[jt]s$)")
        .expect("RE_EXCLUDED_FILE: invalid regex")
});

static CONSOLE_METHODS: [(&str, Lazy<Regex>); 6] = [
    (
        "log",
        Lazy::new(|| Regex::new(r"console\.log\s*\(").expect("console.log regex")),
    ),
    (
        "debug",
        Lazy::new(|| Regex::new(r"console\.debug\s*\(").expect("console.debug regex")),
    ),
    (
        "info",
        Lazy::new(|| Regex::new(r"console\.info\s*\(").expect("console.info regex")),
    ),
    (
        "trace",
        Lazy::new(|| Regex::new(r"console\.trace\s*\(").expect("console.trace regex")),
    ),
    (
        "table",
        Lazy::new(|| Regex::new(r"console\.table\s*\(").expect("console.table regex")),
    ),
    (
        "dir",
        Lazy::new(|| Regex::new(r"console\.dir\s*\(").expect("console.dir regex")),
    ),
];

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            if RE_EXCLUDED_FILE.is_match(file_path) {
                return Vec::new();
            }

            CONSOLE_METHODS
                .iter()
                .filter_map(|(method, pattern)| {
                    find_non_comment_match(content, pattern).map(|line_num| Violation {
                        rule: format!("console-{}", method),
                        severity: Severity::Low,
                        failure: "Remove console statement or use a proper logger".to_string(),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    })
                })
                .collect()
        }),
    }
}
