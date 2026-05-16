use super::{Rule, Severity, Violation, RE_JS_FILE};
use regex::Regex;
use std::sync::LazyLock;

static RE_SW_SCOPE_ROOT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"navigator\.serviceWorker\.register\s*\([^)]*\bscope\s*:\s*['"`]/['"`]"#)
        .expect("RE_SW_SCOPE_ROOT: invalid regex")
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str, lines: &[(u32, &str)]| {
            let mut violations = Vec::new();
            for mat in RE_SW_SCOPE_ROOT.find_iter(content) {
                let line_num = u32::try_from(content[..mat.start()].matches('\n').count() + 1)
                    .unwrap_or(u32::MAX);
                if !lines.iter().any(|(n, _)| *n == line_num) {
                    continue;
                }
                violations.push(Violation {
                    rule: super::rule_id::SERVICE_WORKER_SCOPE_ROOT.to_owned(),
                    severity: Severity::Medium,
                    fix: "Narrow Service Worker scope to a specific path (e.g. { scope: '/app/' }) instead of root '/'.".to_owned(),
                    file: file_path.to_owned(),
                    line: Some(line_num),
                });
            }
            violations
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        let r = rule();
        if !r.file_pattern.is_match(path) {
            return Vec::new();
        }
        r.check(content, path, &super::super::non_comment_lines(content))
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
    fn detects_multi_line_register() {
        let v = check(
            "navigator.serviceWorker.register('/sw.js', {\n  scope: '/',\n});",
            "/src/app.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn ignores_comment() {
        assert!(check(
            "// navigator.serviceWorker.register('/sw.js', { scope: '/' });",
            "/src/app.ts",
        )
        .is_empty());
    }
}
