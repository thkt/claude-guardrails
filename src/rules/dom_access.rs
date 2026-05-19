use super::{find_match_in_lines, Rule, Severity, Violation, RE_REACT_FILE};
use regex::Regex;
use std::sync::LazyLock;

struct DomAccess {
    pattern: &'static LazyLock<Regex>,
    method: &'static str,
}

static RE_GET_BY_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"document\.getElementById\s*\(").expect("RE_GET_BY_ID: invalid regex")
});

static RE_QUERY_SELECTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"document\.querySelector(All)?\s*\(").expect("RE_QUERY_SELECTOR: invalid regex")
});

static RE_GET_ELEMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"document\.getElementsBy(ClassName|TagName|Name)\s*\(")
        .expect("RE_GET_ELEMENTS: invalid regex")
});

static RE_CREATE_ELEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"document\.createElement\s*\(").expect("RE_CREATE_ELEMENT: invalid regex")
});

static RE_APPEND_CHILD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.appendChild\s*\(").expect("RE_APPEND_CHILD: invalid regex"));

static DOM_ACCESS: LazyLock<[DomAccess; 5]> = LazyLock::new(|| {
    [
        DomAccess {
            pattern: &RE_GET_BY_ID,
            method: "document.getElementById",
        },
        DomAccess {
            pattern: &RE_QUERY_SELECTOR,
            method: "document.querySelector",
        },
        DomAccess {
            pattern: &RE_GET_ELEMENTS,
            method: "document.getElementsBy*",
        },
        DomAccess {
            pattern: &RE_CREATE_ELEMENT,
            method: "document.createElement",
        },
        DomAccess {
            pattern: &RE_APPEND_CHILD,
            method: "appendChild",
        },
    ]
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_REACT_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();

        for access in DOM_ACCESS.iter() {
            if let Some(line_num) = find_match_in_lines(lines, access.pattern) {
                violations.push(Violation {
                    rule: super::rule_id::DOM_ACCESS.to_owned(),
                    severity: Severity::Medium,
                    fix: format!(
                        "Avoid {} in React. Use useRef or React state instead.",
                        access.method
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

    fn check(content: &str, path: &str) -> Vec<Violation> {
        if !RULE.file_pattern.is_match(path) {
            return Vec::new();
        }
        RULE.check(content, path, &super::super::non_comment_lines(content))
    }

    #[test]
    fn detects_get_element_by_id() {
        let content = r"const el = document.getElementById('root');";
        let violations = check(content, "/src/components/App.tsx");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("getElementById"));
    }

    #[test]
    fn detects_query_selector() {
        let content = r"const el = document.querySelector('.container');";
        let violations = check(content, "/src/components/App.tsx");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_create_element() {
        let content = r"const div = document.createElement('div');";
        let violations = check(content, "/src/components/App.tsx");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn allows_in_non_react_files() {
        let content = r"const el = document.getElementById('root');";
        assert!(check(content, "/src/utils/dom.ts").is_empty());
        assert!(check(content, "/src/lib/helper.js").is_empty());
    }

    #[test]
    fn allows_useref_pattern() {
        let content = r"
            const ref = useRef<HTMLDivElement>(null);
            return <div ref={ref}>Hello</div>;
        ";
        assert!(check(content, "/src/components/App.tsx").is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r"
            // Don't use document.getElementById in React
            const ref = useRef(null);
        ";
        assert!(check(content, "/src/components/App.tsx").is_empty());
    }
}
