use super::{Rule, Severity, Violation, RE_JS_FILE};
use regex::Regex;
use std::sync::LazyLock;

static RE_HTML_CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]<[a-zA-Z][^>]*>['"]\s*\+\s*[a-zA-Z_$]"#)
        .expect("RE_HTML_CONCAT: invalid regex")
});

static RE_HTML_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"`[^`]{0,500}<[a-zA-Z][^>]{0,200}>[^`]{0,500}\$\{[^`]{0,500}`")
        .expect("RE_HTML_TEMPLATE: invalid regex")
});

static RE_HTML_JOIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]<[a-zA-Z][^>]*>['"]"#).expect("RE_HTML_JOIN: invalid regex")
});
static RE_JOIN_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.join\s*\(").expect("RE_JOIN_CALL: invalid regex"));

const JOIN_PROXIMITY_LINES: u32 = 5;

fn make_violation(file_path: &str, line_num: u32) -> Violation {
    Violation {
        rule: super::rule_id::RAW_HTML.to_owned(),
        severity: Severity::High,
        fix: "Use DOM APIs or framework templating instead of HTML string concatenation."
            .to_owned(),
        file: file_path.to_owned(),
        line: Some(line_num),
    }
}

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let mut violations = Vec::new();
        let mut html_tag_line: Option<u32> = None;

        for &(line_num, line) in lines {
            if RE_HTML_CONCAT.is_match(line) {
                violations.push(make_violation(file_path, line_num));
                continue;
            }

            if RE_HTML_TEMPLATE.is_match(line) {
                violations.push(make_violation(file_path, line_num));
                continue;
            }

            if RE_HTML_JOIN.is_match(line) {
                html_tag_line = Some(line_num);
            }
            if let Some(tag_line) = html_tag_line {
                if RE_JOIN_CALL.is_match(line)
                    && line_num.saturating_sub(tag_line) <= JOIN_PROXIMITY_LINES
                {
                    violations.push(make_violation(file_path, line_num));
                    html_tag_line = None;
                } else if line_num.saturating_sub(tag_line) > JOIN_PROXIMITY_LINES {
                    html_tag_line = None;
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
        RULE.check(content, path, &super::super::non_comment_lines(content))
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

    // Known limitation: multiline template literals are not detected
    // because regex requires backticks on the same line
    #[test]
    fn multiline_template_not_detected() {
        let content = "const html = `\n  <div>\n    ${variable}\n  </div>\n`;";
        assert!(check(content, "/src/render.ts").is_empty());
    }
}
