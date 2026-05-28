use super::{Rule, Severity, Violation, RE_ALL_FILES};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_KNOWN_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_KNOWN_PREFIX",
        r#"["'](sk-[a-zA-Z0-9]{10,}|AKIA[A-Z0-9]{12,}|ghp_[a-zA-Z0-9]{10,}|gho_[a-zA-Z0-9]{10,}|ghs_[a-zA-Z0-9]{10,}|xoxb-[a-zA-Z0-9]{10,}|xoxp-[a-zA-Z0-9]{10,}|glpat-[a-zA-Z0-9]{10,}|sk_live_[a-zA-Z0-9]{10,}|rk_live_[a-zA-Z0-9]{10,}|SG\.[a-zA-Z0-9]{10,})["']"#,
    )
});

static RE_BEARER_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_BEARER_TOKEN",
        r#"["'](Bearer|Basic)\s+[A-Za-z0-9._+/=-]{20,}["']"#,
    )
});

static RE_AWS_KEY: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_AWS_KEY",
        r#"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["'][A-Za-z0-9/+=]{16,}["']"#,
    )
});

// Value length >= 4 to reduce false positives (SEC-004)
static RE_PASSWORD_ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_PASSWORD_ASSIGN",
        r#"(?i)\b(password|passwd|secret|api_?key|apikey|access_?token|private_?key)\s*[:=]\s*["'][^"']{4,200}["']"#,
    )
});

static RE_TEST_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_TEST_PREFIX",
        r"(?i)\b(test_?|mock_?|fake_?|dummy_?|example_?|placeholder_?)\w*\s*=",
    )
});

struct SecretPattern {
    pattern: &'static LazyLock<Regex>,
    apply_test_exclusion: bool,
    message: &'static str,
}

static SECRET_PATTERNS: [SecretPattern; 4] = [
    SecretPattern {
        pattern: &RE_KNOWN_PREFIX,
        apply_test_exclusion: false,
        message: "Hardcoded API token detected (matches known prefix pattern). Use environment variables or secret management.",
    },
    SecretPattern {
        pattern: &RE_BEARER_TOKEN,
        apply_test_exclusion: false,
        message: "Hardcoded Bearer/Basic token detected. Use environment variables or secret management.",
    },
    SecretPattern {
        pattern: &RE_PASSWORD_ASSIGN,
        apply_test_exclusion: true,
        message: "Hardcoded password/secret assignment detected. Use environment variables or secret management.",
    },
    SecretPattern {
        pattern: &RE_AWS_KEY,
        apply_test_exclusion: false,
        message: "Hardcoded AWS access key detected. Use environment variables or secret management.",
    },
];

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_ALL_FILES.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for &(line_num, line) in lines {
            let is_test_line = RE_TEST_PREFIX.is_match(line);
            for sp in &SECRET_PATTERNS {
                if sp.apply_test_exclusion && is_test_line {
                    continue;
                }
                if sp.pattern.is_match(line) {
                    violations.push(Violation {
                        rule: super::rule_id::HARDCODED_SECRET.to_owned(),
                        severity: Severity::Critical,
                        fix: sp.message.to_owned(),
                        file: file_path.to_owned(),
                        line: Some(line_num),
                    });
                    break;
                }
            }
        }

        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        if !RULE.file_pattern.is_match(path) {
            return Vec::new();
        }
        super::super::check_rule(&RULE, content, path)
    }

    #[test]
    fn detects_sk_prefix_api_key() {
        let v = check(r#"const API_KEY = "sk-abc123def456";"#, "/src/config.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_bearer_token() {
        let v = check(
            r#""Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature""#,
            "/src/api.ts",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_password_assignment() {
        let v = check(r#"const password = "s3cret";"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_aws_key() {
        let v = check(r#"const AKIA_KEY = "AKIAIOSFODNN7EXAMPLE";"#, "/src/aws.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_github_token() {
        let v = check(
            r#"const ghp_token = "ghp_xxxxxxxxxxxxxxxxxxxx";"#,
            "/src/github.ts",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn ignores_test_prefix() {
        assert!(check(r#"const test_token = "sk-abc";"#, "/src/test.ts").is_empty());
    }

    #[test]
    fn ignores_mock_prefix() {
        assert!(check(r#"const mock_password = "x";"#, "/src/mock.ts").is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check(r#"// const API_KEY = "sk-abc123";"#, "/src/config.ts").is_empty());
    }

    #[test]
    fn ignores_non_sensitive() {
        assert!(check(r#"const theme = "dark";"#, "/src/config.ts").is_empty());
    }

    #[test]
    fn test_prefix_does_not_suppress_secret_value() {
        let v = check(
            r#"const test_key = "sk-REALSECRETKEY123";"#,
            "/src/config.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_prefix_does_not_suppress_bearer() {
        let v = check(
            r#"const test_auth = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature""#,
            "/src/config.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn ignores_short_password_value() {
        assert!(check(r#"const config = { password: "***" };"#, "/src/config.ts").is_empty());
    }

    #[test]
    fn detects_password_with_sufficient_length() {
        let v = check(r#"const password = "s3cret123";"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_slack_bot_token() {
        let v = check(r#"const token = "xoxb-abcdefghij1234";"#, "/src/slack.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_gitlab_token() {
        let v = check(r#"const token = "glpat-abcdefghij1234";"#, "/src/gitlab.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn error_messages_differ_per_pattern() {
        let v_prefix = check(r#"const key = "sk-abc123def456";"#, "/src/config.ts");
        let v_bearer = check(
            r#""Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature""#,
            "/src/api.ts",
        );
        assert_eq!(v_prefix.len(), 1);
        assert_eq!(v_bearer.len(), 1);
        assert_ne!(v_prefix[0].fix, v_bearer[0].fix);
        assert!(v_prefix[0].fix.contains("known prefix pattern"));
        assert!(v_bearer[0].fix.contains("Bearer/Basic"));
    }

    #[test]
    fn test_prefix_matches_without_declaration_keyword() {
        assert!(check(r#"test_password = "s3cret123";"#, "/src/config.ts").is_empty());
    }
}
