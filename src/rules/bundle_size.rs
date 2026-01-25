use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

struct LargeImport {
    pattern: &'static Lazy<Regex>,
    package: &'static str,
    suggestion: &'static str,
}

static RE_LODASH_FULL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import\s+[\w]+\s+from\s+['"]lodash['"]"#).expect("RE_LODASH_FULL: invalid regex")
});

static RE_MOMENT_FULL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import\s+[\w]+\s+from\s+['"]moment['"]"#).expect("RE_MOMENT_FULL: invalid regex")
});

static RE_MUI_ICONS_FULL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import\s+\*\s+as\s+[\w]+\s+from\s+['"]@mui/icons-material['"]"#)
        .expect("RE_MUI_ICONS_FULL: invalid regex")
});

static RE_DATE_FNS_FULL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import\s+\*\s+as\s+[\w]+\s+from\s+['"]date-fns['"]"#)
        .expect("RE_DATE_FNS_FULL: invalid regex")
});

static RE_RXJS_FULL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import\s+\*\s+as\s+[\w]+\s+from\s+['"]rxjs['"]"#)
        .expect("RE_RXJS_FULL: invalid regex")
});

static LARGE_IMPORTS: Lazy<[LargeImport; 5]> = Lazy::new(|| {
    [
        LargeImport {
            pattern: &RE_LODASH_FULL,
            package: "lodash",
            suggestion: "Use 'lodash-es' with tree-shaking or import specific functions: import { map } from 'lodash-es'",
        },
        LargeImport {
            pattern: &RE_MOMENT_FULL,
            package: "moment",
            suggestion: "Use 'date-fns' or 'dayjs' instead (moment is deprecated and large)",
        },
        LargeImport {
            pattern: &RE_MUI_ICONS_FULL,
            package: "@mui/icons-material",
            suggestion: "Import specific icons: import { Home } from '@mui/icons-material'",
        },
        LargeImport {
            pattern: &RE_DATE_FNS_FULL,
            package: "date-fns",
            suggestion: "Import specific functions: import { format } from 'date-fns'",
        },
        LargeImport {
            pattern: &RE_RXJS_FULL,
            package: "rxjs",
            suggestion: "Import specific operators: import { map } from 'rxjs/operators'",
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for import in LARGE_IMPORTS.iter() {
                if let Some(line_num) = find_non_comment_match(content, import.pattern) {
                    violations.push(Violation {
                        rule: "bundle-size".to_string(),
                        severity: Severity::Medium,
                        failure: format!(
                            "Full {} import increases bundle size. {}",
                            import.package, import.suggestion
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
        rule().check(content, "/src/utils/helper.ts")
    }

    #[test]
    fn detects_full_lodash_import() {
        let content = r#"import _ from 'lodash';"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("lodash"));
    }

    #[test]
    fn detects_full_moment_import() {
        let content = r#"import moment from 'moment';"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("moment"));
    }

    #[test]
    fn detects_full_mui_icons_import() {
        let content = r#"import * as Icons from '@mui/icons-material';"#;
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn allows_specific_lodash_import() {
        let content = r#"import { map, filter } from 'lodash-es';"#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_specific_mui_icon_import() {
        let content = r#"import { Home, Settings } from '@mui/icons-material';"#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_date_fns_specific_import() {
        let content = r#"import { format, parseISO } from 'date-fns';"#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_dayjs() {
        let content = r#"import dayjs from 'dayjs';"#;
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r#"
            // import _ from 'lodash' - don't do this
            import { map } from 'lodash-es';
        "#;
        assert!(check(content).is_empty());
    }
}
