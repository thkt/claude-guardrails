use super::{Rule, Severity, Violation, RE_ALL_FILES, RE_TEST_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_SRC_DIR: LazyLock<Regex> = LazyLock::new(|| regex_or_die("RE_SRC_DIR", r"/src/"));

static TEST_DIR_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        regex_or_die("test_location:__tests__dir", r"/__tests__/"),
        regex_or_die("test_location:test_dir", r"/tests?/"),
    ]
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_ALL_FILES.clone(),
    checker: Box::new(|_content: &str, file_path: &str, _lines: &[(u32, &str)]| {
        if !RE_SRC_DIR.is_match(file_path) {
            return Vec::new();
        }

        if RE_TEST_FILE.is_match(file_path)
            || TEST_DIR_PATTERNS.iter().any(|p| p.is_match(file_path))
        {
            return vec![Violation {
                rule: super::rule_id::TEST_LOCATION.to_owned(),
                severity: Severity::Medium,
                fix: "Test files should be in tests/ or __tests__/ directory outside src/"
                    .to_owned(),
                file: file_path.to_owned(),
                line: None,
                origin: None,
                no_demote: None,
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
