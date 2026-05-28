use super::{find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

struct LargeImport {
    pattern: &'static LazyLock<Regex>,
    package: &'static str,
    suggestion: &'static str,
}

static RE_LODASH_FULL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_LODASH_FULL",
        r#"import\s+[\w]+\s+from\s+['"]lodash['"]"#,
    )
});

static RE_MOMENT_FULL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_MOMENT_FULL",
        r#"import\s+[\w]+\s+from\s+['"]moment['"]"#,
    )
});

static RE_MUI_ICONS_FULL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_MUI_ICONS_FULL",
        r#"import\s+\*\s+as\s+[\w]+\s+from\s+['"]@mui/icons-material['"]"#,
    )
});

static RE_DATE_FNS_FULL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_DATE_FNS_FULL",
        r#"import\s+\*\s+as\s+[\w]+\s+from\s+['"]date-fns['"]"#,
    )
});

static RE_RXJS_FULL: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_RXJS_FULL",
        r#"import\s+\*\s+as\s+[\w]+\s+from\s+['"]rxjs['"]"#,
    )
});

static LARGE_IMPORTS: LazyLock<[LargeImport; 5]> = LazyLock::new(|| {
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

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for import in LARGE_IMPORTS.iter() {
            if let Some(line_num) = find_match_in_lines(lines, import.pattern) {
                violations.push(Violation {
                    rule: super::rule_id::BUNDLE_SIZE.to_owned(),
                    severity: Severity::Medium,
                    fix: format!(
                        "Full {} import increases bundle size. {}",
                        import.package, import.suggestion
                    ),
                    file: file_path.to_owned(),
                    line: Some(line_num),
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
        super::super::check_rule(&RULE, content, "/src/utils/helper.ts")
    }

    #[test]
    fn detects_full_lodash_import() {
        let content = r"import _ from 'lodash';";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("lodash"));
    }

    #[test]
    fn detects_full_moment_import() {
        let content = r"import moment from 'moment';";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("moment"));
    }

    #[test]
    fn detects_full_mui_icons_import() {
        let content = r"import * as Icons from '@mui/icons-material';";
        let violations = check(content);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn allows_specific_lodash_import() {
        let content = r"import { map, filter } from 'lodash-es';";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_specific_mui_icon_import() {
        let content = r"import { Home, Settings } from '@mui/icons-material';";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_date_fns_specific_import() {
        let content = r"import { format, parseISO } from 'date-fns';";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_dayjs() {
        let content = r"import dayjs from 'dayjs';";
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r"
            // import _ from 'lodash' - don't do this
            import { map } from 'lodash-es';
        ";
        assert!(check(content).is_empty());
    }
}
