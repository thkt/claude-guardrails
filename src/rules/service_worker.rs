use super::{find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_SW_SCOPE_ROOT: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_SW_SCOPE_ROOT",
        r#"navigator\.serviceWorker\.register\s*\([^;\n]*?\bscope\s*:\s*['"`]/['"`]"#,
    )
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();
        if let Some(line_num) = find_match_in_lines(lines, &RE_SW_SCOPE_ROOT) {
            violations.push(Violation {
                rule: super::rule_id::SERVICE_WORKER_SCOPE_ROOT.to_owned(),
                severity: Severity::Medium,
                fix: "Narrow Service Worker scope to a specific path (e.g. { scope: '/app/' }) instead of root '/'.".to_owned(),
                file: file_path.to_owned(),
                line: Some(line_num),
                origin: None,
            });
        }
        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        if !RULE.file_pattern.is_match(path) {
            return Vec::new();
        }
        super::super::check_rule(&RULE, content, path)
    }

    #[test]
    fn detects_explicit_root_scope_single_quote() {
        let v = check(
            "navigator.serviceWorker.register('/sw.js', { scope: '/' });",
            "/src/app.ts",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    #[test]
    fn allows_omitted_scope() {
        assert!(check("navigator.serviceWorker.register('/sw.js');", "/src/app.ts").is_empty());
    }

    #[test]
    fn detects_explicit_root_scope_double_quote() {
        let v = check(
            r#"navigator.serviceWorker.register("/sw.js", { scope: "/" });"#,
            "/src/app.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_explicit_root_scope_backtick() {
        let v = check(
            "navigator.serviceWorker.register(`/sw.js`, { scope: `/` });",
            "/src/app.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_non_root_scope() {
        assert!(check(
            "navigator.serviceWorker.register('/sw.js', { scope: '/app/' });",
            "/src/app.ts",
        )
        .is_empty());
    }

    #[test]
    fn allows_unrelated_register_call() {
        assert!(check(
            "mockServiceWorker.register('/sw.js', { scope: '/' });",
            "/src/app.ts",
        )
        .is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check(
            "// navigator.serviceWorker.register('/sw.js', { scope: '/' });",
            "/src/app.ts",
        )
        .is_empty());
    }

    #[test]
    fn detects_nested_call_argument() {
        let v = check(
            "navigator.serviceWorker.register(new URL('/sw.js', import.meta.url), { scope: '/' });",
            "/src/app.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_second_call_on_same_line() {
        let v = check(
            "navigator.serviceWorker.register('/a.js'); navigator.serviceWorker.register('/b.js', { scope: '/' });",
            "/src/app.ts",
        );
        assert_eq!(v.len(), 1);
    }
}
