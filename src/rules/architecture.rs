use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

struct LayerViolation {
    from_pattern: &'static Lazy<Regex>,
    importing: &'static Lazy<Regex>,
    failure: &'static str,
}

static RE_UTILS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/utils/").expect("RE_UTILS: invalid regex"));
static RE_SERVICES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/services/").expect("RE_SERVICES: invalid regex"));
static RE_COMPONENTS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/components/").expect("RE_COMPONENTS: invalid regex"));

static RE_IMPORT_UI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"from\s+['"].*/(components|hooks|pages|features)/"#)
        .expect("RE_IMPORT_UI: invalid regex")
});
static RE_IMPORT_UI_NO_FEATURES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"from\s+['"].*/(components|hooks|pages)/"#)
        .expect("RE_IMPORT_UI_NO_FEATURES: invalid regex")
});
static RE_IMPORT_PAGES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"from\s+['"].*\/pages/"#).expect("RE_IMPORT_PAGES: invalid regex"));

static LAYER_VIOLATIONS: Lazy<[LayerViolation; 3]> = Lazy::new(|| {
    [
        LayerViolation {
            from_pattern: &RE_UTILS,
            importing: &RE_IMPORT_UI,
            failure: "Remove import or move function to appropriate layer (utils should not depend on UI)",
        },
        LayerViolation {
            from_pattern: &RE_SERVICES,
            importing: &RE_IMPORT_UI_NO_FEATURES,
            failure: "Use callback parameters or events instead (services should not depend on UI)",
        },
        LayerViolation {
            from_pattern: &RE_COMPONENTS,
            importing: &RE_IMPORT_PAGES,
            failure: "Pass data via props instead (components should not import pages)",
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut result = Vec::new();

            for v in LAYER_VIOLATIONS.iter() {
                if !v.from_pattern.is_match(file_path) {
                    continue;
                }
                if let Some(line_num) = find_non_comment_match(content, v.importing) {
                    result.push(Violation {
                        rule: "architecture".to_string(),
                        severity: Severity::High,
                        failure: v.failure.to_string(),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    });
                }
            }

            result
        }),
    }
}
