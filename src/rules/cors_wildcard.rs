use crate::ast;
use crate::rules::{rule_id, Severity, Violation, RE_JS_FILE};
use oxc_ast::ast::{
    Argument, CallExpression, Expression, ObjectExpression, ObjectPropertyKind, Program,
    PropertyKey,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

const CORS_HEADER: &str = "Access-Control-Allow-Origin";
const WILDCARD: &str = "*";

const HEADER_METHODS: [&str; 3] = ["setHeader", "header", "appendHeader"];

const FIX_MESSAGE: &str =
    "CORS wildcard '*' grants any origin. Restrict to a specific URL or an allowlist array.";

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    ast::with_parsed_program(content, file_path, |program, line_offsets| {
        check_program(program, line_offsets, file_path)
    })
    .unwrap_or_default()
}

pub fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
) -> Vec<Violation> {
    if !RE_JS_FILE.is_match(file_path) {
        return Vec::new();
    }
    let mut visitor = CorsVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
    };
    visitor.visit_program(program);
    visitor.violations
}

struct CorsVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
}

impl CorsVisitor<'_> {
    fn push(&mut self, span: Span) {
        self.violations.push(Violation {
            rule: rule_id::CORS_WILDCARD.to_owned(),
            severity: Severity::Medium,
            fix: FIX_MESSAGE.to_owned(),
            file: self.file_path.to_owned(),
            line: Some(ast::span_to_line(self.line_offsets, span)),
        });
    }
}

fn is_cors_call(call: &CallExpression) -> bool {
    ast::is_ident(&call.callee, "cors")
}

fn is_header_setter_call(call: &CallExpression) -> bool {
    let Some((_, method)) = ast::member_name(&call.callee) else {
        return false;
    };
    HEADER_METHODS.contains(&method)
}

fn cors_options_has_wildcard_origin(call: &CallExpression) -> bool {
    call.arguments.iter().any(|arg| {
        let Some(Expression::ObjectExpression(obj)) = arg.as_expression() else {
            return false;
        };
        origin_is_wildcard(obj)
    })
}

fn origin_is_wildcard(obj: &ObjectExpression) -> bool {
    obj.properties.iter().any(|prop| {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            return false;
        };
        property_key_is(&p.key, "origin") && string_value_is(&p.value, WILDCARD)
    })
}

fn property_key_is(key: &PropertyKey, name: &str) -> bool {
    match key {
        PropertyKey::StaticIdentifier(id) => id.name == name,
        PropertyKey::StringLiteral(s) => s.value == name,
        _ => false,
    }
}

fn string_value_is(expr: &Expression, expected: &str) -> bool {
    matches!(expr, Expression::StringLiteral(s) if s.value == expected)
}

fn header_setter_is_acao_wildcard(call: &CallExpression) -> bool {
    if call.arguments.len() < 2 {
        return false;
    }
    let Some(name) = string_arg(&call.arguments[0]) else {
        return false;
    };
    let Some(value) = string_arg(&call.arguments[1]) else {
        return false;
    };
    name.eq_ignore_ascii_case(CORS_HEADER) && value == WILDCARD
}

fn string_arg<'a>(arg: &'a Argument<'a>) -> Option<&'a str> {
    let Expression::StringLiteral(s) = arg.as_expression()? else {
        return None;
    };
    Some(s.value.as_str())
}

impl<'a> Visit<'a> for CorsVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if (is_cors_call(call) && cors_options_has_wildcard_origin(call))
            || (is_header_setter_call(call) && header_setter_is_acao_wildcard(call))
        {
            self.push(call.span);
        }
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn check_js(code: &str) -> Vec<Violation> {
        check(code, "/src/app.ts")
    }

    // T-001: cors({ origin: '*' }) → blocked, Medium
    #[test]
    fn detects_cors_options_with_wildcard_origin() {
        let v = check_js("app.use(cors({ origin: '*' }));");
        assert_eq!(v.len(), 1, "expected one violation, got: {:?}", v);
        assert_eq!(v[0].severity, Severity::Medium);
        assert_eq!(v[0].rule, rule_id::CORS_WILDCARD);
    }

    // T-002: res.setHeader('Access-Control-Allow-Origin', '*') → blocked
    #[test]
    fn detects_set_header_acao_wildcard() {
        let v = check_js("res.setHeader('Access-Control-Allow-Origin', '*');");
        assert_eq!(v.len(), 1, "expected one violation, got: {:?}", v);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    // T-003: res.header('Access-Control-Allow-Origin', '*') → blocked (Express)
    #[test]
    fn detects_express_header_acao_wildcard() {
        let v = check_js("res.header('Access-Control-Allow-Origin', '*');");
        assert_eq!(v.len(), 1);
    }

    // T-004: cors with specific origin → allowed
    #[test]
    fn allows_cors_with_specific_origin() {
        let v = check_js("app.use(cors({ origin: 'https://example.com' }));");
        assert!(v.is_empty(), "specific origin must not flag: {:?}", v);
    }

    // T-005: cors with array origin → allowed (allowlist)
    #[test]
    fn allows_cors_with_array_origin() {
        let v = check_js("app.use(cors({ origin: ['https://a.com', 'https://b.com'] }));");
        assert!(v.is_empty(), "array origin must not flag: {:?}", v);
    }

    // T-006: cors with function origin → allowed (dynamic decision)
    #[test]
    fn allows_cors_with_function_origin() {
        let v = check_js("app.use(cors({ origin: (origin, cb) => cb(null, true) }));");
        assert!(v.is_empty(), "function origin must not flag: {:?}", v);
    }

    // T-007: setHeader with different header name → allowed
    #[test]
    fn allows_set_header_for_different_header() {
        let v = check_js("res.setHeader('Content-Type', '*');");
        assert!(v.is_empty(), "non-ACAO header must not flag: {:?}", v);
    }

    // T-008: non-JS files out of scope
    #[test]
    fn ignores_non_js_files() {
        let v = check("app.use(cors({ origin: '*' }));", "/docs/README.md");
        assert!(v.is_empty(), "non-js file must not flag: {:?}", v);
    }

    // T-009: dynamic origin expression → skipped (static analysis cannot resolve)
    #[test]
    fn skips_dynamic_origin_expression() {
        let v = check_js("app.use(cors({ origin: getAllowedOrigin() }));");
        assert!(v.is_empty(), "dynamic origin must skip: {:?}", v);
    }

    // T-010: empty file / fail-open on parse error
    #[test]
    fn empty_file_returns_no_violation() {
        assert!(check_js("").is_empty());
    }

    #[test]
    fn fail_open_on_invalid_syntax() {
        assert!(check_js("function { invalid !!!").is_empty());
    }

    // T-011: violation carries correct line number
    #[test]
    fn reports_correct_line_number() {
        let code = "const opts = {};\napp.use(cors({ origin: '*' }));";
        let v = check_js(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(2));
    }

    // T-012: case-insensitive header name match (HTTP header is case-insensitive per RFC)
    #[test]
    fn detects_case_insensitive_header_name() {
        let v = check_js("res.setHeader('access-control-allow-origin', '*');");
        assert_eq!(v.len(), 1);
    }

    // T-013: NFR-001 perf < 10ms/file
    #[test]
    fn nfr001_cors_under_10ms() {
        let content = concat!(
            "app.use(cors({ origin: '*' }));\n",
            "res.setHeader('Access-Control-Allow-Origin', '*');\n",
            "res.header('Access-Control-Allow-Origin', '*');\n",
            "app.use(cors({ origin: 'https://example.com' }));\n",
            "app.use(cors({ origin: ['https://a.com'] }));\n",
            "app.use(cors({ origin: (o, cb) => cb(null, true) }));\n",
            "res.setHeader('Content-Type', 'text/html');\n",
        );
        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = check(content, "/src/app.ts");
        }
        let elapsed = start.elapsed();
        let per_file_us = elapsed.as_micros() / iterations;
        eprintln!("NFR-001 cors-wildcard: {per_file_us}us/file ({iterations} iterations)");
        assert!(
            per_file_us < 10_000,
            "AST cors-wildcard check exceeded 10ms/file: {per_file_us}us"
        );
    }
}
