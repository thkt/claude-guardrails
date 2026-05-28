use super::{find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

struct LayerViolation {
    from_pattern: &'static LazyLock<Regex>,
    importing: &'static LazyLock<Regex>,
    fix: &'static str,
}

static RE_UTILS: LazyLock<Regex> = LazyLock::new(|| regex_or_die("RE_UTILS", r"/utils/"));
static RE_SERVICES: LazyLock<Regex> = LazyLock::new(|| regex_or_die("RE_SERVICES", r"/services/"));
static RE_COMPONENTS: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_COMPONENTS", r"/components/"));

static RE_IMPORT_UI: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_IMPORT_UI",
        r#"from\s+['"].*/(components|hooks|pages|features)/"#,
    )
});
static RE_IMPORT_UI_NO_FEATURES: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_IMPORT_UI_NO_FEATURES",
        r#"from\s+['"].*/(components|hooks|pages)/"#,
    )
});
static RE_IMPORT_PAGES: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_IMPORT_PAGES", r#"from\s+['"].*\/pages/"#));

static LAYER_VIOLATIONS: LazyLock<[LayerViolation; 3]> = LazyLock::new(|| {
    [
        LayerViolation {
            from_pattern: &RE_UTILS,
            importing: &RE_IMPORT_UI,
            fix: "Remove import or move function to appropriate layer (utils should not depend on UI)",
        },
        LayerViolation {
            from_pattern: &RE_SERVICES,
            importing: &RE_IMPORT_UI_NO_FEATURES,
            fix: "Use callback parameters or events instead (services should not depend on UI)",
        },
        LayerViolation {
            from_pattern: &RE_COMPONENTS,
            importing: &RE_IMPORT_PAGES,
            fix: "Pass data via props instead (components should not import pages)",
        },
    ]
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut result = Vec::new();

        for v in LAYER_VIOLATIONS.iter() {
            if !v.from_pattern.is_match(file_path) {
                continue;
            }
            if let Some(line_num) = find_match_in_lines(lines, v.importing) {
                result.push(Violation {
                    rule: super::rule_id::ARCHITECTURE.to_owned(),
                    severity: Severity::High,
                    fix: v.fix.to_owned(),
                    file: file_path.to_owned(),
                    line: Some(line_num),
                });
            }
        }

        result
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        super::super::check_rule(&RULE, content, path)
    }

    #[test]
    fn detects_utils_importing_ui() {
        let content = r"import { Button } from '../components/Button';";
        let violations = check(content, "/src/utils/formatter.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("utils should not depend on UI"));
    }

    #[test]
    fn detects_services_importing_ui() {
        let content = r"import { useAuth } from '../hooks/useAuth';";
        let violations = check(content, "/src/services/api.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0]
            .fix
            .contains("services should not depend on UI"));
    }

    #[test]
    fn detects_components_importing_pages() {
        let content = r"import { HomePage } from '../pages/Home';";
        let violations = check(content, "/src/components/Header.tsx");
        assert_eq!(violations.len(), 1);
        assert!(violations[0]
            .fix
            .contains("components should not import pages"));
    }

    #[test]
    fn allows_valid_imports() {
        let cases = [
            (
                r"import { format } from '../utils/date';",
                "/src/components/Calendar.tsx",
            ),
            (
                r"import { api } from '../services/api';",
                "/src/hooks/useData.ts",
            ),
            (
                r"import { Button } from '../components/Button';",
                "/src/pages/Home.tsx",
            ),
        ];
        for (content, path) in cases {
            assert!(
                check(content, path).is_empty(),
                "Should allow: {content} in {path}"
            );
        }
    }
}
