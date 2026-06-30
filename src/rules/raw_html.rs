use super::{Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_compile::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_HTML_CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_HTML_CONCAT",
        r#"['"]<[a-zA-Z][^>]*>['"]\s*\+\s*[a-zA-Z_$]"#,
    )
});

static RE_HTML_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_HTML_TEMPLATE",
        r"`[^`]{0,500}<[a-zA-Z][^>]{0,200}>[^`]{0,500}\$\{[^`]{0,500}`",
    )
});

static RE_HTML_JOIN: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_HTML_JOIN", r#"['"]<[a-zA-Z][^>]*>['"]"#));
// Inline `['<div>', x].join('')`: the array literal holding the HTML tag is
// joined on the same line, so there is no bound identifier to track. The `]`
// before `.join(` (no `;` in between, so still one statement) ties the join to
// that literal directly. The cross-line case goes through RE_HTML_BIND instead.
static RE_HTML_INLINE_JOIN: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_HTML_INLINE_JOIN",
        r#"['"]<[a-zA-Z][^>]*>['"][^;\n]*\]\s*\.join\s*\("#,
    )
});
// Identifier bound to the array literal that holds the HTML tag, so a later
// `.join()` can be matched against its receiver instead of mere proximity.
static RE_HTML_BIND: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_HTML_BIND",
        r"(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=",
    )
});
// Captures the receiver identifier of a `.join(` call (`parts.join('')` → parts).
static RE_JOIN_RECEIVER: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_JOIN_RECEIVER", r"([a-zA-Z_$][\w$]*)\s*\.join\s*\("));

const JOIN_PROXIMITY_LINES: u32 = 5;

fn make_violation(file_path: &str, line_num: u32) -> Violation {
    Violation {
        rule: super::rule_id::RAW_HTML.to_owned(),
        severity: Severity::High,
        fix: "Use DOM APIs or framework templating instead of HTML string concatenation."
            .to_owned(),
        file: file_path.to_owned(),
        line: Some(line_num),
        origin: None,
    }
}

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();
        // (line, identifier) of the most recent array literal that holds an HTML
        // tag and is bound to a name. A `.join()` fires only when its receiver is
        // that identifier, so an unrelated nearby join no longer trips the rule.
        let mut html_array: Option<(u32, &str)> = None;

        for &(line_num, line) in lines {
            if RE_HTML_CONCAT.is_match(line) {
                violations.push(make_violation(file_path, line_num));
                continue;
            }

            if RE_HTML_TEMPLATE.is_match(line) {
                violations.push(make_violation(file_path, line_num));
                continue;
            }

            if RE_HTML_INLINE_JOIN.is_match(line) {
                violations.push(make_violation(file_path, line_num));
                continue;
            }

            if RE_HTML_JOIN.is_match(line) {
                if let Some(caps) = RE_HTML_BIND.captures(line) {
                    html_array = Some((line_num, caps.get(1).unwrap().as_str()));
                }
            }
            if let Some((tag_line, ident)) = html_array {
                if line_num.saturating_sub(tag_line) > JOIN_PROXIMITY_LINES {
                    html_array = None;
                } else if RE_JOIN_RECEIVER
                    .captures(line)
                    .is_some_and(|c| c.get(1).unwrap().as_str() == ident)
                {
                    violations.push(make_violation(file_path, line_num));
                    html_array = None;
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
    fn detects_html_concat_with_variable() {
        let v = check(r"const html = '<div>' + userInput;", "/src/render.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    #[test]
    fn detects_template_literal_with_html() {
        let v = check("const html = `<div>${variable}</div>`;", "/src/render.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_html_join() {
        let content = r"const parts = ['<div>', userInput, '</div>'];
const html = parts.join('');";
        let v = check(content, "/src/render.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_inline_array_literal_join() {
        // Recall guard (#376): the identifier-binding FP-3 fix must not drop the
        // inline `['<tag>', x].join('')` form, where the array literal is joined on
        // the same line with no bound name to track.
        let v = check("const html = ['<div>', x].join('');", "/src/render.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_literal_only_concat() {
        assert!(check(r"const html = '<div>' + '</div>';", "/src/render.ts").is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check("// const html = '<div>' + x;", "/src/render.ts").is_empty());
    }

    #[test]
    fn ignores_distant_join() {
        let mut lines = vec![r"const tags = ['<br>'];".to_owned()];
        for _ in 0..10 {
            lines.push("const x = doSomething();".to_owned());
        }
        lines.push("const csv = values.join(',');".to_owned());
        let content = lines.join("\n");
        assert!(check(&content, "/src/render.ts").is_empty());
    }

    #[test]
    fn ignores_unrelated_join_near_html_literal() {
        // FP #376: a `.join()` on an unrelated identifier within proximity of an
        // HTML-tag literal must not fire. Only a join on the array that holds the
        // literal builds HTML.
        let content = "const tags = ['<br>'];\nconst csv = values.join(',');";
        assert!(check(content, "/src/render.ts").is_empty());
    }

    // Known limitation: multiline template literals are not detected
    // because regex requires backticks on the same line
    #[test]
    fn multiline_template_not_detected() {
        let content = "const html = `\n  <div>\n    ${variable}\n  </div>\n`;";
        assert!(check(content, "/src/render.ts").is_empty());
    }
}
