use super::{Rule, Severity, Violation, RE_ALL_FILES};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static SENSITIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        regex_or_die("sensitive_file:env", r"\.env(\.[a-zA-Z]+)?$"),
        regex_or_die("sensitive_file:credentials", r"credentials\.[a-zA-Z]+$"),
        regex_or_die("sensitive_file:_credentials", r"_credentials\.[a-zA-Z]+$"),
        regex_or_die("sensitive_file:_key", r"_key\.[a-zA-Z]+$"),
        regex_or_die("sensitive_file:_secret", r"_secret\.[a-zA-Z]+$"),
        regex_or_die("sensitive_file:pem", r"\.pem$"),
        regex_or_die("sensitive_file:key", r"\.key$"),
        regex_or_die("sensitive_file:id_rsa", r"id_rsa"),
        regex_or_die("sensitive_file:id_ed25519", r"id_ed25519"),
    ]
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_ALL_FILES.clone(),
    checker: Box::new(|_content: &str, file_path: &str, _lines: &[(u32, &str)]| {
        if SENSITIVE_PATTERNS.iter().any(|p| p.is_match(file_path)) {
            return vec![Violation {
                rule: super::rule_id::SENSITIVE_FILE.to_owned(),
                severity: Severity::Critical,
                fix: "Do not write to sensitive files. Use environment variables or secret management.".to_owned(),
                file: file_path.to_owned(),
                line: None,
            }];
        }
        Vec::new()
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str) -> Vec<Violation> {
        RULE.check("", path, &[])
    }

    #[test]
    fn detects_env_file() {
        assert_eq!(check("/project/.env").len(), 1);
        assert_eq!(check("/project/.env.local").len(), 1);
        assert_eq!(check("/project/.env.production").len(), 1);
    }

    #[test]
    fn detects_credentials_file() {
        assert_eq!(check("/project/credentials.json").len(), 1);
        assert_eq!(check("/project/aws_credentials.json").len(), 1);
    }

    #[test]
    fn detects_key_files() {
        assert_eq!(check("/project/api_key.json").len(), 1);
        assert_eq!(check("/project/private.pem").len(), 1);
        assert_eq!(check("/project/server.key").len(), 1);
        assert_eq!(check("~/.ssh/id_rsa").len(), 1);
        assert_eq!(check("~/.ssh/id_ed25519").len(), 1);
    }

    #[test]
    fn allows_normal_files() {
        assert!(check("/project/src/index.ts").is_empty());
        assert!(check("/project/README.md").is_empty());
        assert!(check("/project/package.json").is_empty());
    }

    #[test]
    fn blocks_env_example_for_safety() {
        // .env.example is often committed as a template, but we block it for safety
        assert_eq!(check("/project/.env.example").len(), 1);
    }
}
