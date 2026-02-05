use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

struct WeakCrypto {
    pattern: &'static Lazy<Regex>,
    algorithm: &'static str,
    suggestion: &'static str,
}

static RE_MD5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(createHash\s*\(\s*['"]md5['"]|MD5\s*\(|\.md5\s*\()"#)
        .expect("RE_MD5: invalid regex")
});

static RE_SHA1: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(createHash\s*\(\s*['"]sha1['"]|SHA1\s*\(|\.sha1\s*\()"#)
        .expect("RE_SHA1: invalid regex")
});

static RE_DES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(createCipher\s*\(\s*['"]des['"]|DES\s*\(|\.des\s*\()"#)
        .expect("RE_DES: invalid regex")
});

static RE_RC4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(createCipher\s*\(\s*['"]rc4['"]|RC4\s*\(|\.rc4\s*\()"#)
        .expect("RE_RC4: invalid regex")
});

static WEAK_CRYPTO: Lazy<[WeakCrypto; 4]> = Lazy::new(|| {
    [
        WeakCrypto {
            pattern: &RE_MD5,
            algorithm: "MD5",
            suggestion: "Use SHA-256 or SHA-3 instead",
        },
        WeakCrypto {
            pattern: &RE_SHA1,
            algorithm: "SHA-1",
            suggestion: "Use SHA-256 or SHA-3 instead",
        },
        WeakCrypto {
            pattern: &RE_DES,
            algorithm: "DES",
            suggestion: "Use AES-256 instead",
        },
        WeakCrypto {
            pattern: &RE_RC4,
            algorithm: "RC4",
            suggestion: "Use AES-256 instead",
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for crypto in WEAK_CRYPTO.iter() {
                if let Some(line_num) = find_non_comment_match(content, crypto.pattern) {
                    violations.push(Violation {
                        rule: "crypto-weak".to_string(),
                        severity: Severity::High,
                        failure: format!(
                            "{} is cryptographically weak. {}",
                            crypto.algorithm, crypto.suggestion
                        ),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    });
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
        rule().check(content, "/src/utils/hash.ts")
    }

    #[test]
    fn detects_weak_algorithms() {
        let cases = [
            (
                "crypto.createHash('md5').update(data).digest('hex');",
                "MD5",
            ),
            (
                "crypto.createHash('sha1').update(data).digest('hex');",
                "SHA-1",
            ),
            ("crypto.createCipher('des', key);", "DES"),
        ];
        for (content, expected) in cases {
            let violations = check(content);
            assert_eq!(violations.len(), 1, "Should detect: {}", expected);
            assert!(violations[0].failure.contains(expected));
        }
    }

    #[test]
    fn allows_strong_algorithms() {
        let content = r#"
            const hash = crypto.createHash('sha256').update(data).digest('hex');
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        "#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r#"
            // Don't use createHash('md5') - it's weak
            const hash = crypto.createHash('sha256').update(data).digest('hex');
        "#;
        assert!(check(content).is_empty());
    }
}
