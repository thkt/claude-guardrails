use super::{find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

struct NamingIssue {
    pattern: &'static LazyLock<Regex>,
    file_pattern: Option<&'static LazyLock<Regex>>,
    additional_check: Option<&'static LazyLock<Regex>>,
    fix: &'static str,
    severity: Severity,
}

static RE_LOWERCASE_ARROW: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_LOWERCASE_ARROW",
        r"const\s+[a-z][a-zA-Z]*\s*=\s*\([^)]*\)\s*=>",
    )
});
static RE_COMPONENT_FILE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_COMPONENT_FILE", r"/components/.*\.tsx$"));
static RE_JSX_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_JSX_RETURN",
        r"const\s+[a-z][a-zA-Z]*\s*=\s*\([^)]*\)\s*=>\s*[{(][^}]*<",
    )
});

static RE_NON_USE_ARROW: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_NON_USE_ARROW",
        r"const\s+[a-tv-z][a-zA-Z]*\s*=.*=>\s*\{",
    )
});
static RE_HOOKS_FILE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_HOOKS_FILE", r"/hooks/.*\.ts$"));
static RE_HOOK_USAGE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_HOOK_USAGE", r"use(State|Effect|Callback|Memo)"));

static RE_LOWERCASE_INTERFACE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_LOWERCASE_INTERFACE", r"interface\s+[a-z]"));
static RE_LOWERCASE_TYPE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_LOWERCASE_TYPE", r"type\s+[a-z][a-zA-Z]*\s*="));

static NAMING_ISSUES: LazyLock<[NamingIssue; 4]> = LazyLock::new(|| {
    [
        NamingIssue {
            pattern: &RE_LOWERCASE_ARROW,
            file_pattern: Some(&RE_COMPONENT_FILE),
            additional_check: Some(&RE_JSX_RETURN),
            fix: "Rename to PascalCase (e.g., myComponent → MyComponent)",
            severity: Severity::Medium,
        },
        NamingIssue {
            pattern: &RE_NON_USE_ARROW,
            file_pattern: Some(&RE_HOOKS_FILE),
            additional_check: Some(&RE_HOOK_USAGE),
            fix: "Rename to useXxx (custom hooks must start with 'use')",
            severity: Severity::High,
        },
        NamingIssue {
            pattern: &RE_LOWERCASE_INTERFACE,
            file_pattern: None,
            additional_check: None,
            fix: "Rename interface to PascalCase",
            severity: Severity::Low,
        },
        NamingIssue {
            pattern: &RE_LOWERCASE_TYPE,
            file_pattern: None,
            additional_check: None,
            fix: "Rename type to PascalCase",
            severity: Severity::Low,
        },
    ]
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for issue in NAMING_ISSUES.iter() {
            if let Some(fp) = issue.file_pattern {
                if !fp.is_match(file_path) {
                    continue;
                }
            }
            if let Some(ac) = issue.additional_check {
                if find_match_in_lines(lines, ac).is_none() {
                    continue;
                }
            }
            if let Some(line_num) = find_match_in_lines(lines, issue.pattern) {
                violations.push(Violation {
                    rule: super::rule_id::NAMING_CONVENTION.to_owned(),
                    severity: issue.severity,
                    fix: issue.fix.to_owned(),
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

    fn check(content: &str, path: &str) -> Vec<Violation> {
        super::super::check_rule(&RULE, content, path)
    }

    #[test]
    fn detects_lowercase_component() {
        let content = r"const myComponent = () => { return <div>Hello</div>; };";
        let violations = check(content, "/src/components/MyComponent.tsx");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("PascalCase"));
    }

    #[test]
    fn detects_non_use_hook() {
        let content = r"const fetchData = () => { const [data] = useState(null); return data; };";
        let violations = check(content, "/src/hooks/useFetch.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("useXxx"));
    }

    #[test]
    fn detects_lowercase_interface() {
        let content = "interface user { name: string; }";
        let violations = check(content, "/src/types.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("interface"));
    }

    #[test]
    fn detects_lowercase_type() {
        let content = "type userRole = 'admin' | 'user';";
        let violations = check(content, "/src/types.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("type"));
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
            assert!(check(content, path).is_empty(), "Should allow: {content}");
        }
    }
}
