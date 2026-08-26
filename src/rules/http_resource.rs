use super::{Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_HTTP_URL: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_HTTP_URL", r#"["']http://[^"']+["']"#));

static RE_LOCAL: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_LOCAL", r"http://(localhost|127\.0\.0\.1)"));

pub(super) static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for &(line_num, line) in lines {
            for mat in RE_HTTP_URL.find_iter(line) {
                let url_match = mat.as_str();
                if !RE_LOCAL.is_match(url_match) {
                    violations.push(Violation {
                        rule: super::rule_id::HTTP_RESOURCE.to_owned(),
                        severity: Severity::Medium,
                        fix: "Use HTTPS for external resources.".to_owned(),
                        file: file_path.to_owned(),
                        line: Some(line_num),
                        origin: None,
                        no_demote: None,
                    });
                    break;
                }
            }
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
    fn detects_http_fetch() {
        let v = check(r#"fetch("http://api.example.com/data");"#, "/src/api.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    #[test]
    fn detects_http_axios() {
        let v = check(
            r#"axios.get("http://cdn.example.com/lib.js");"#,
            "/src/api.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_localhost() {
        assert!(check(r#"fetch("http://localhost:3000/api");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn allows_loopback() {
        assert!(check(r#"fetch("http://127.0.0.1:8080/api");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn allows_https() {
        assert!(check(r#"fetch("https://api.example.com/data");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check(r#"// fetch("http://x.com/api");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn detects_http_on_line_with_localhost() {
        let content = r#"const urls = ["http://evil.com", "http://localhost:3000"];"#;
        let result = super::super::check_rule(&RULE, content, "/src/api.ts");
        assert_eq!(result.len(), 1);
    }
}
