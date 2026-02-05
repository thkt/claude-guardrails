use super::{Rule, Severity, Violation, RE_ALL_FILES};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_SRC_DIR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/src/").expect("RE_SRC_DIR: invalid regex"));

static TEST_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\.(test|spec)\.[jt]sx?$").expect("test/spec pattern"),
        Regex::new(r"/__tests__/").expect("__tests__ dir pattern"),
        Regex::new(r"/tests?/").expect("test dir pattern"),
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_ALL_FILES.clone(),
        checker: Box::new(|_content: &str, file_path: &str| {
            if !RE_SRC_DIR.is_match(file_path) {
                return Vec::new();
            }

            for pattern in TEST_PATTERNS.iter() {
                if pattern.is_match(file_path) {
                    return vec![Violation {
                        rule: "test-location".to_string(),
                        severity: Severity::Medium,
                        failure:
                            "Test files should be in tests/ or __tests__/ directory outside src/"
                                .to_string(),
                        file: file_path.to_string(),
                        line: None,
                    }];
                }
            }
            Vec::new()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str) -> Vec<Violation> {
        rule().check("", path)
    }

    #[test]
    fn detects_test_file_in_src() {
        assert_eq!(check("/project/src/utils/helper.test.ts").len(), 1);
        assert_eq!(check("/project/src/components/Button.spec.tsx").len(), 1);
    }

    #[test]
    fn detects_tests_dir_in_src() {
        assert_eq!(check("/project/src/__tests__/utils.ts").len(), 1);
        assert_eq!(
            check("/project/src/components/__tests__/Button.ts").len(),
            1
        );
    }

    #[test]
    fn allows_test_file_outside_src() {
        assert!(check("/project/tests/utils/helper.test.ts").is_empty());
        assert!(check("/project/__tests__/components/Button.spec.tsx").is_empty());
    }

    #[test]
    fn allows_normal_files_in_src() {
        assert!(check("/project/src/utils/helper.ts").is_empty());
        assert!(check("/project/src/components/Button.tsx").is_empty());
    }

    #[test]
    fn allows_files_outside_src() {
        assert!(check("/project/lib/utils.ts").is_empty());
        assert!(check("/project/app/page.tsx").is_empty());
    }
}
