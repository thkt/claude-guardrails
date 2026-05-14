use super::{find_match_in_lines, Rule, Severity, Violation};
use regex::Regex;
use std::sync::LazyLock;

struct EscapeBypass {
    pattern: &'static LazyLock<Regex>,
    hint: &'static str,
}

static RE_TRIPLE_STASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{\{[^{}]+\}\}\}").expect("RE_TRIPLE_STASH: invalid regex"));

static RE_MUSTACHE_AMP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{\s*&[^{}]+\}\}").expect("RE_MUSTACHE_AMP: invalid regex"));

static RE_NO_ESCAPE_TRUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]?noEscape['"]?\s*:\s*true"#).expect("RE_NO_ESCAPE_TRUE: invalid regex")
});

static RE_TEMPLATE_OR_JS_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.(tsx?|jsx?|hbs|handlebars|mustache)$")
        .expect("RE_TEMPLATE_OR_JS_FILE: invalid regex")
});

static ESCAPE_BYPASSES: LazyLock<[EscapeBypass; 3]> = LazyLock::new(|| {
    [
        EscapeBypass {
            pattern: &RE_TRIPLE_STASH,
            hint: "Triple-stash {{{ }}} bypasses auto-escape. Use {{ }} (double-stash) or sanitize input before rendering.",
        },
        EscapeBypass {
            pattern: &RE_MUSTACHE_AMP,
            hint: "Ampersand {{& }} bypasses auto-escape. Use {{ }} (double-stash) or sanitize input before rendering.",
        },
        EscapeBypass {
            pattern: &RE_NO_ESCAPE_TRUE,
            hint: "noEscape: true disables auto-escape globally. Remove the option or set noEscape: false, and sanitize untrusted input before rendering.",
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_TEMPLATE_OR_JS_FILE.clone(),
        checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
            let mut violations = Vec::new();
            for bypass in ESCAPE_BYPASSES.iter() {
                if let Some(line_num) = find_match_in_lines(lines, bypass.pattern) {
                    violations.push(Violation {
                        rule: super::rule_id::DISABLE_MUSTACHE_ESCAPE.to_owned(),
                        severity: Severity::Medium,
                        fix: bypass.hint.to_owned(),
                        file: file_path.to_owned(),
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
        let r = rule();
        if !r.file_pattern.is_match(path) {
            return Vec::new();
        }
        r.check(content, path, &super::super::non_comment_lines(content))
    }

    #[test]
    fn detects_triple_stash_in_hbs() {
        let v = check("<div>{{{userInput}}}</div>", "/templates/post.hbs");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
        assert!(v[0].fix.contains("Triple-stash"));
    }

    #[test]
    fn detects_triple_stash_in_mustache() {
        let v = check("<div>{{{name}}}</div>", "/templates/card.mustache");
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("Triple-stash"));
    }

    #[test]
    fn detects_mustache_ampersand() {
        let v = check("<div>{{&content}}</div>", "/templates/card.mustache");
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("Ampersand"));
    }

    #[test]
    fn detects_mustache_ampersand_with_space() {
        let v = check("<div>{{ &content }}</div>", "/templates/card.mustache");
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("Ampersand"));
    }

    #[test]
    fn detects_no_escape_option() {
        let v = check(
            "const tpl = Handlebars.compile(src, { noEscape: true });",
            "/src/render.ts",
        );
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("noEscape"));
    }

    #[test]
    fn detects_no_escape_quoted_key() {
        let v = check(
            r#"const tpl = Handlebars.compile(src, { "noEscape": true });"#,
            "/src/render.ts",
        );
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("noEscape"));
    }

    #[test]
    fn detects_triple_stash_in_js_template_literal() {
        let v = check("const tpl = `<div>{{{name}}}</div>`;", "/src/template.ts");
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("Triple-stash"));
    }

    #[test]
    fn reports_multiple_distinct_bypasses() {
        let content = r#"
            const tpl1 = `<div>{{{name}}}</div>`;
            const tpl2 = Handlebars.compile(src, { noEscape: true });
        "#;
        let v = check(content, "/src/template.ts");
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|x| x.rule == "disable-mustache-escape"));
        assert!(v.iter().any(|x| x.fix.contains("Triple-stash")));
        assert!(v.iter().any(|x| x.fix.contains("noEscape")));
    }

    #[test]
    fn allows_normal_mustache_double_stash() {
        assert!(check("<div>{{name}}</div>", "/templates/card.mustache").is_empty());
    }

    #[test]
    fn allows_js_object_literal() {
        assert!(check("const obj = { a: 1, b: 2 };", "/src/data.ts").is_empty());
    }

    #[test]
    fn allows_jsx_expression_with_object() {
        assert!(check("<Comp style={{ color: 'red' }} />", "/src/Comp.tsx").is_empty());
    }

    #[test]
    fn allows_no_escape_false() {
        assert!(check(
            "const tpl = Handlebars.compile(src, { noEscape: false });",
            "/src/render.ts"
        )
        .is_empty());
    }

    #[test]
    fn allows_non_template_file() {
        assert!(check("<div>{{{x}}}</div>", "/styles/main.css").is_empty());
        assert!(check("<div>{{{x}}}</div>", "/data/sample.py").is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r#"
            // const tpl = `<div>{{{name}}}</div>`;
            const safe = "regular";
        "#;
        assert!(check(content, "/src/template.ts").is_empty());
    }
}
