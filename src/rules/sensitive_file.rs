use super::{Rule, Severity, Violation, RE_ALL_FILES};
use regex::Regex;
use std::sync::LazyLock;

static SENSITIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"\.env(\.[a-zA-Z]+)?$").expect("env pattern"),
        Regex::new(r"credentials\.[a-zA-Z]+$").expect("credentials pattern"),
        Regex::new(r"_credentials\.[a-zA-Z]+$").expect("_credentials pattern"),
        Regex::new(r"_key\.[a-zA-Z]+$").expect("_key pattern"),
        Regex::new(r"_secret\.[a-zA-Z]+$").expect("_secret pattern"),
        Regex::new(r"\.pem$").expect("pem pattern"),
        Regex::new(r"\.key$").expect("key pattern"),
        Regex::new(r"id_rsa").expect("id_rsa pattern"),
        Regex::new(r"id_ed25519").expect("id_ed25519 pattern"),
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
