use super::{find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

struct WeakCrypto {
    pattern: &'static LazyLock<Regex>,
    algorithm: &'static str,
    suggestion: &'static str,
}

// The createHash / createCipher arm matches the algorithm name case-insensitively
// (`createHash('MD5')` is the same weak sink as `'md5'`, FN-1 #377). The `(?i:..)`
// is scoped to the quoted literal only — the bare `MD5(` / `.md5(` arms stay
// case-sensitive so a lowercased name cannot match the "des(" tail of common
// identifiers like `includes(` (the FP class closed in #376).
static RE_MD5: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_MD5",
        r#"(createHash\s*\(\s*['"](?i:md5)['"]|MD5\s*\(|\.md5\s*\()"#,
    )
});

static RE_SHA1: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_SHA1",
        r#"(createHash\s*\(\s*['"](?i:sha1)['"]|SHA1\s*\(|\.sha1\s*\()"#,
    )
});

static RE_DES: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_DES",
        r#"(createCipher\s*\(\s*['"](?i:des)['"]|DES\s*\(|\.des\s*\()"#,
    )
});

static RE_RC4: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_RC4",
        r#"(createCipher\s*\(\s*['"](?i:rc4)['"]|RC4\s*\(|\.rc4\s*\()"#,
    )
});

static WEAK_CRYPTO: LazyLock<[WeakCrypto; 4]> = LazyLock::new(|| {
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

pub(super) static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for crypto in WEAK_CRYPTO.iter() {
            if let Some(line_num) = find_match_in_lines(lines, crypto.pattern) {
                violations.push(Violation {
                    rule: super::rule_id::CRYPTO_WEAK.to_owned(),
                    severity: Severity::High,
                    fix: format!(
                        "{} is cryptographically weak. {}",
                        crypto.algorithm, crypto.suggestion
                    ),
                    file: file_path.to_owned(),
                    line: Some(line_num),
                    origin: None,
                    no_demote: None,
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
        super::super::check_rule(&RULE, content, "/src/utils/hash.ts")
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
            ("crypto.createCipher('rc4', key);", "RC4"),
        ];
        for (content, expected) in cases {
            let violations = check(content);
            assert_eq!(violations.len(), 1, "Should detect: {expected}");
            assert!(violations[0].fix.contains(expected));
        }
    }

    #[test]
    fn detects_uppercase_algorithm_names() {
        // FN-1 #377: an uppercase algorithm literal bypassed the lowercase-only
        // createHash / createCipher arm (`createHash('MD5')` slipped through).
        let cases = [
            ("crypto.createHash('MD5').digest('hex');", "MD5"),
            ("crypto.createHash('SHA1').digest('hex');", "SHA-1"),
            ("crypto.createCipher('DES', key);", "DES"),
            ("crypto.createCipher('RC4', key);", "RC4"),
        ];
        for (content, expected) in cases {
            let violations = check(content);
            assert_eq!(violations.len(), 1, "Should detect: {expected}");
            assert!(violations[0].fix.contains(expected));
        }
    }

    #[test]
    fn ignores_des_substring_in_identifier() {
        // The bare `DES(` arm stays case-sensitive: a case-insensitive bare arm
        // would match the "des(" tail of common identifiers (`arr.includes(x)`),
        // re-opening the FP class closed in #376.
        let content = "if (arr.includes(x)) { obj.provides(y); }";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_strong_algorithms() {
        let content = r"
            const hash = crypto.createHash('sha256').update(data).digest('hex');
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r"
            // Don't use createHash('md5') - it's weak
            const hash = crypto.createHash('sha256').update(data).digest('hex');
        ";
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_weak_algorithm_in_inline_comment() {
        // FP #376: an inline comment trailing live code must not be scanned.
        let content = "const h = crypto.createHash('sha256'); // replaced createHash('md5')";
        assert!(check(content).is_empty());
    }
}
