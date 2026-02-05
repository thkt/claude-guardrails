use super::{Rule, Severity, Violation, RE_ALL_FILES};
use once_cell::sync::Lazy;
use regex::Regex;

static GENERATED_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\.generated\.[a-zA-Z]+$").expect("generated pattern"),
        Regex::new(r"\.g\.(ts|js|dart)$").expect("g pattern"),
        Regex::new(r"_generated\.[a-zA-Z]+$").expect("_generated pattern"),
        Regex::new(r"\.auto\.[a-zA-Z]+$").expect("auto pattern"),
        Regex::new(r"/generated/").expect("generated dir pattern"),
        Regex::new(r"/__generated__/").expect("__generated__ dir pattern"),
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_ALL_FILES.clone(),
        checker: Box::new(|_content: &str, file_path: &str| {
            for pattern in GENERATED_PATTERNS.iter() {
                if pattern.is_match(file_path) {
                    return vec![Violation {
                        rule: "generated-file".to_string(),
                        severity: Severity::High,
                        failure: "Do not edit generated files directly. Modify the source and regenerate.".to_string(),
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
