use super::{Rule, Severity, Violation, RE_ALL_FILES};
use crate::regex_util::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static GENERATED_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        regex_or_die("generated_file:generated", r"\.generated\.[a-zA-Z]+$"),
        regex_or_die("generated_file:g", r"\.g\.(ts|js|dart)$"),
        regex_or_die("generated_file:_generated", r"_generated\.[a-zA-Z]+$"),
        regex_or_die("generated_file:auto", r"\.auto\.[a-zA-Z]+$"),
        regex_or_die("generated_file:generated_dir", r"/generated/"),
        regex_or_die("generated_file:__generated__dir", r"/__generated__/"),
    ]
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_ALL_FILES.clone(),
    checker: Box::new(|_content: &str, file_path: &str, _lines: &[(u32, &str)]| {
        for pattern in GENERATED_PATTERNS.iter() {
            if pattern.is_match(file_path) {
                return vec![Violation {
                    rule: super::rule_id::GENERATED_FILE.to_owned(),
                    severity: Severity::High,
                    fix: "Do not edit generated files directly. Modify the source and regenerate."
                        .to_owned(),
                    file: file_path.to_owned(),
                    line: None,
                }];
            }
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
    fn detects_generated_ts() {
        assert_eq!(check("/src/api/client.generated.ts").len(), 1);
        assert_eq!(check("/src/api/types.generated.js").len(), 1);
    }

    #[test]
    fn detects_g_files() {
        assert_eq!(check("/src/models/user.g.ts").len(), 1);
        assert_eq!(check("/lib/models/user.g.dart").len(), 1);
    }

    #[test]
    fn detects_underscore_generated() {
        assert_eq!(check("/src/api/schema_generated.ts").len(), 1);
    }

    #[test]
    fn detects_auto_files() {
        assert_eq!(check("/src/types/api.auto.ts").len(), 1);
    }

    #[test]
    fn detects_generated_directory() {
        assert_eq!(check("/src/generated/types.ts").len(), 1);
        assert_eq!(check("/src/__generated__/graphql.ts").len(), 1);
    }

    #[test]
    fn allows_normal_files() {
        assert!(check("/src/components/Button.tsx").is_empty());
        assert!(check("/src/utils/helper.ts").is_empty());
        assert!(check("/src/api/client.ts").is_empty());
    }
}
