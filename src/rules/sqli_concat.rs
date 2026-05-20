use crate::ast;
use crate::rules::{rule_id, Severity, Violation, RE_JS_FILE};
use oxc_ast::ast::{BinaryOperator, CallExpression, Expression, Program, TemplateLiteral};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

const SQL_KEYWORDS: [&str; 13] = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "DROP", "CREATE", "ALTER", "TRUNCATE",
    "GRANT", "REVOKE", "UNION", "EXEC",
];

const FIX_MESSAGE: &str =
    "Dynamic SQL via string interpolation/concatenation. Use parameterized query: db.execute(sql, [params]).";

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    super::ast_test_check(content, file_path, |program, line_offsets| {
        check_program(program, line_offsets, file_path)
    })
}

#[cfg(test)]
fn check_fail_open(content: &str, file_path: &str) -> Vec<Violation> {
    super::ast_fail_open_check(content, file_path, |program, line_offsets| {
        check_program(program, line_offsets, file_path)
    })
}

pub fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
) -> Vec<Violation> {
    if !RE_JS_FILE.is_match(file_path) {
        return Vec::new();
    }
    let mut visitor = SqliVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
    };
    visitor.visit_program(program);
    visitor.violations
}

struct SqliVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
}

impl SqliVisitor<'_> {
    fn push(&mut self, span: Span) {
        self.violations.push(Violation {
            rule: rule_id::SQLI_CONCAT.to_owned(),
            severity: Severity::High,
            fix: FIX_MESSAGE.to_owned(),
            file: self.file_path.to_owned(),
            line: Some(ast::span_to_line(self.line_offsets, span)),
        });
    }
}

#[derive(Default)]
struct ConcatParts {
    literals: String,
    has_dynamic: bool,
}

fn expression_is_dynamic_sql(expr: &Expression) -> bool {
    match expr {
        Expression::TemplateLiteral(tl) => {
            !tl.expressions.is_empty() && template_has_sql_keyword(tl)
        }
        Expression::BinaryExpression(be) if be.operator == BinaryOperator::Addition => {
            let mut parts = ConcatParts::default();
            collect_concat_parts(&be.left, &mut parts);
            collect_concat_parts(&be.right, &mut parts);
            parts.has_dynamic && contains_sql_keyword(&parts.literals)
        }
        _ => false,
    }
}

fn collect_concat_parts(expr: &Expression, parts: &mut ConcatParts) {
    match expr {
        Expression::StringLiteral(s) => {
            parts.literals.push(' ');
            parts.literals.push_str(s.value.as_str());
        }
        Expression::TemplateLiteral(tl) => {
            for q in &tl.quasis {
                parts.literals.push(' ');
                parts.literals.push_str(q.value.raw.as_str());
            }
            if !tl.expressions.is_empty() {
                parts.has_dynamic = true;
            }
        }
        Expression::BinaryExpression(be) if be.operator == BinaryOperator::Addition => {
            collect_concat_parts(&be.left, parts);
            collect_concat_parts(&be.right, parts);
        }
        Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => {}
        _ => parts.has_dynamic = true,
    }
}

fn template_has_sql_keyword(tl: &TemplateLiteral) -> bool {
    tl.quasis
        .iter()
        .any(|q| contains_sql_keyword(q.value.raw.as_str()))
}

fn is_console_member_call(call: &CallExpression) -> bool {
    let Some((object, _)) = ast::member_name(&call.callee) else {
        return false;
    };
    ast::is_ident(object, "console")
}

fn contains_sql_keyword(s: &str) -> bool {
    s.split(|c: char| !c.is_ascii_alphabetic())
        .any(|w| SQL_KEYWORDS.iter().any(|kw| w.eq_ignore_ascii_case(kw)))
}

impl<'a> Visit<'a> for SqliVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !is_console_member_call(call)
            && call
                .arguments
                .iter()
                .filter_map(|a| a.as_expression())
                .any(expression_is_dynamic_sql)
        {
            self.push(call.span);
        }
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_js(code: &str) -> Vec<Violation> {
        check(code, "/src/app.ts")
    }

    // T-001: TemplateLiteral with SQL keyword + interpolation → blocked
    #[test]
    fn detects_template_literal_with_sql_keyword_and_interpolation() {
        let v = check_js("db.execute(`SELECT * FROM users WHERE id = ${userId}`);");
        assert_eq!(v.len(), 1, "expected one violation, got: {v:?}");
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::SQLI_CONCAT);
    }

    // T-002: string concat (+) with SQL keyword + non-literal → blocked
    #[test]
    fn detects_string_concat_with_sql_keyword() {
        let v =
            check_js(r#"connection.query("SELECT * FROM users WHERE name = '" + input + "'");"#);
        assert_eq!(v.len(), 1, "expected one violation, got: {v:?}");
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-003: prepared statement with `?` placeholder → allowed
    #[test]
    fn allows_prepared_statement_with_question_mark() {
        let v = check_js(r#"db.execute("SELECT * FROM users WHERE id = ?", [userId]);"#);
        assert!(v.is_empty(), "prepared statement must not flag: {v:?}");
    }

    // T-004: prepared statement with `$1` numbered placeholder → allowed
    #[test]
    fn allows_prepared_statement_with_numbered_placeholder() {
        let v = check_js(r#"db.query("SELECT * FROM users WHERE id = $1", [userId]);"#);
        assert!(v.is_empty(), "numbered placeholder must not flag: {v:?}");
    }

    // T-005: static TemplateLiteral (no interpolation) → allowed
    #[test]
    fn allows_static_template_literal() {
        let v = check_js("db.execute(`SELECT * FROM users`);");
        assert!(v.is_empty(), "static template must not flag: {v:?}");
    }

    // T-006: ORM where clause (no raw SQL string) → allowed
    #[test]
    fn allows_orm_where_clause() {
        let v = check_js("prisma.user.findMany({ where: { id: userId } });");
        assert!(v.is_empty(), "ORM where must not flag: {v:?}");
    }

    // T-007: console.* (log/info/warn/error/debug) with dynamic SQL → allowed
    #[test]
    fn allows_console_member_calls_with_dynamic_sql() {
        for method in ["log", "info", "warn", "error", "debug"] {
            let code = format!("console.{method}(`SELECT failed for id=${{id}}`);");
            let v = check_js(&code);
            assert!(v.is_empty(), "console.{method} must not flag: {v:?}");
        }
    }

    // T-008: non-JS files are out of scope
    #[test]
    fn ignores_non_js_files() {
        let v = check_fail_open(
            "db.execute(`SELECT * FROM users WHERE id = ${userId}`);",
            "/docs/README.md",
        );
        assert!(v.is_empty(), "non-js file must not flag: {v:?}");
    }

    // T-009: violation carries correct line number
    #[test]
    fn reports_correct_line_number() {
        let code = "const id = 1;\nconst sql = db.execute(`SELECT * FROM t WHERE id = ${id}`);";
        let v = check_js(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(2));
    }

    // T-010: empty file does not panic, returns no violations
    #[test]
    fn empty_file_returns_no_violation() {
        assert!(check_js("").is_empty());
    }

    // T-011: fail-open on invalid syntax (parser failure returns no violations)
    #[test]
    fn fail_open_on_invalid_syntax() {
        assert!(check_fail_open("function { invalid !!!", "/src/app.ts").is_empty());
    }

    // T-012: SQL keyword inside non-call context (variable assignment) is not flagged
    #[test]
    fn ignores_sql_template_outside_call_argument() {
        let v = check_js("const sql = `SELECT * FROM t WHERE id = ${id}`;");
        assert!(
            v.is_empty(),
            "template assigned to variable without call sink must not flag: {v:?}"
        );
    }

    // T-014: dynamic TemplateLiteral participating in `+` concat → blocked
    #[test]
    fn detects_dynamic_template_in_concat_chain() {
        let v = check_js("db.query(`SELECT * FROM users WHERE id = ${id}` + suffix);");
        assert_eq!(v.len(), 1, "dynamic template in `+` chain must flag: {v:?}");
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-015: NFR-001: AST parse + check < 10ms per file
    #[test]
    fn nfr001_sqli_under_10ms() {
        let content = concat!(
            "db.execute(`SELECT * FROM users WHERE id = ${userId}`);\n",
            "connection.query(\"SELECT * FROM users WHERE name = '\" + input + \"'\");\n",
            "db.execute(\"SELECT * FROM users WHERE id = ?\", [userId]);\n",
            "db.query(\"SELECT * FROM users WHERE id = $1\", [userId]);\n",
            "db.execute(`SELECT * FROM users`);\n",
            "prisma.user.findMany({ where: { id: userId } });\n",
            "console.log(`SELECT failed for id=${id}`);\n",
        );
        super::super::assert_under_10ms("sqli-concat", 100, || {
            let _ = check(content, "/src/app.ts");
        });
    }
}
