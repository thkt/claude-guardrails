use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

struct NamingIssue {
    pattern: &'static Lazy<Regex>,
    file_pattern: Option<&'static Lazy<Regex>>,
    additional_check: Option<&'static Lazy<Regex>>,
    failure: &'static str,
    severity: Severity,
}

static RE_LOWERCASE_ARROW: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"const\s+[a-z][a-zA-Z]*\s*=\s*\([^)]*\)\s*=>")
        .expect("RE_LOWERCASE_ARROW: invalid regex")
});
static RE_COMPONENT_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/components/.*\.tsx$").expect("RE_COMPONENT_FILE: invalid regex"));
static RE_JSX_RETURN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"const\s+[a-z][a-zA-Z]*\s*=\s*\([^)]*\)\s*=>\s*[{(][^}]*<")
        .expect("RE_JSX_RETURN: invalid regex")
});

static RE_NON_USE_ARROW: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"const\s+[a-tv-z][a-zA-Z]*\s*=.*=>\s*\{").expect("RE_NON_USE_ARROW: invalid regex")
});
static RE_HOOKS_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/hooks/.*\.ts$").expect("RE_HOOKS_FILE: invalid regex"));
static RE_HOOK_USAGE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"use(State|Effect|Callback|Memo)").expect("RE_HOOK_USAGE: invalid regex")
});

static RE_LOWERCASE_INTERFACE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"interface\s+[a-z]").expect("RE_LOWERCASE_INTERFACE: invalid regex"));
static RE_LOWERCASE_TYPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"type\s+[a-z][a-zA-Z]*\s*=").expect("RE_LOWERCASE_TYPE: invalid regex")
});

static NAMING_ISSUES: Lazy<[NamingIssue; 4]> = Lazy::new(|| {
    [
        NamingIssue {
            pattern: &RE_LOWERCASE_ARROW,
            file_pattern: Some(&RE_COMPONENT_FILE),
            additional_check: Some(&RE_JSX_RETURN),
            failure: "Rename to PascalCase (e.g., myComponent → MyComponent)",
            severity: Severity::Medium,
        },
        NamingIssue {
            pattern: &RE_NON_USE_ARROW,
            file_pattern: Some(&RE_HOOKS_FILE),
            additional_check: Some(&RE_HOOK_USAGE),
            failure: "Rename to useXxx (custom hooks must start with 'use')",
            severity: Severity::High,
        },
        NamingIssue {
            pattern: &RE_LOWERCASE_INTERFACE,
            file_pattern: None,
            additional_check: None,
            failure: "Rename interface to PascalCase",
            severity: Severity::Low,
        },
        NamingIssue {
            pattern: &RE_LOWERCASE_TYPE,
            file_pattern: None,
            additional_check: None,
            failure: "Rename type to PascalCase",
            severity: Severity::Low,
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for issue in NAMING_ISSUES.iter() {
                if let Some(fp) = issue.file_pattern {
                    if !fp.is_match(file_path) {
                        continue;
                    }
                }
                if let Some(ac) = issue.additional_check {
                    if find_non_comment_match(content, ac).is_none() {
                        continue;
                    }
                }
                if let Some(line_num) = find_non_comment_match(content, issue.pattern) {
                    violations.push(Violation {
                        rule: "naming-convention".to_string(),
                        severity: issue.severity,
                        failure: issue.failure.to_string(),
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

    fn check(content: &str, path: &str) -> Vec<Violation> {
        rule().check(content, path)
    }

    #[test]
    fn detects_lowercase_component() {
        let content = r#"const myComponent = () => { return <div>Hello</div>; };"#;
        let violations = check(content, "/src/components/MyComponent.tsx");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("PascalCase"));
    }

    #[test]
    fn detects_non_use_hook() {
        let content = r#"const fetchData = () => { const [data] = useState(null); return data; };"#;
        let violations = check(content, "/src/hooks/useFetch.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("useXxx"));
    }

    #[test]
    fn detects_lowercase_interface() {
        let content = "interface user { name: string; }";
        let violations = check(content, "/src/types.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("interface"));
    }

    #[test]
    fn detects_lowercase_type() {
        let content = "type userRole = 'admin' | 'user';";
        let violations = check(content, "/src/types.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("type"));
    }

    #[test]
    fn allows_correct_naming() {
        let cases = [
            (
                "const MyComponent = () => { return <div/>; };",
                "/src/components/MyComponent.tsx",
            ),
            (
                "const useFetch = () => { const [d] = useState(); return d; };",
                "/src/hooks/useFetch.ts",
            ),
            ("interface User { name: string; }", "/src/types.ts"),
            ("type UserRole = 'admin' | 'user';", "/src/types.ts"),
        ];
        for (content, path) in cases {
            assert!(check(content, path).is_empty(), "Should allow: {}", content);
        }
    }
}
