use super::{rule_id, Severity, Violation, RE_JS_FILE};
use crate::ast;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, CallExpression, ComputedMemberExpression, Expression,
    Program, StaticMemberExpression,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

const FIX_MESSAGE: &str = "Validate URL before redirect. Use allowlist or ensure relative path.";

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
    let mut visitor = OpenRedirectVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
    };
    visitor.visit_program(program);
    visitor.violations
}

struct OpenRedirectVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
}

impl OpenRedirectVisitor<'_> {
    fn span_to_line(&self, span: Span) -> u32 {
        ast::span_to_line(self.line_offsets, span)
    }

    fn push(&mut self, span: Span) {
        self.violations.push(Violation {
            rule: rule_id::OPEN_REDIRECT.to_owned(),
            severity: Severity::High,
            fix: FIX_MESSAGE.to_owned(),
            file: self.file_path.to_owned(),
            line: Some(self.span_to_line(span)),
        });
    }
}

impl<'a> Visit<'a> for OpenRedirectVisitor<'_> {
    fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
        if is_location_target(&expr.left) && !is_safe_url_value(&expr.right) {
            self.push(expr.span);
        }
        walk::walk_assignment_expression(self, expr);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if is_location_call(&call.callee) {
            let unsafe_arg = call
                .arguments
                .first()
                .and_then(|a| a.as_expression())
                .is_some_and(|e| !is_safe_url_value(e));
            if unsafe_arg {
                self.push(call.span);
            }
        }
        walk::walk_call_expression(self, call);
    }
}

fn is_location_target(target: &AssignmentTarget) -> bool {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => id.name == "location",
        AssignmentTarget::StaticMemberExpression(sme) => is_location_static_member(sme),
        AssignmentTarget::ComputedMemberExpression(cme) => is_location_computed_member(cme),
        _ => false,
    }
}

fn is_location_static_member(sme: &StaticMemberExpression) -> bool {
    if sme.property.name == "href" && is_location_expr(&sme.object) {
        return true;
    }
    sme.property.name == "location" && is_window_or_document(&sme.object)
}

fn is_location_computed_member(cme: &ComputedMemberExpression) -> bool {
    let Expression::StringLiteral(s) = &cme.expression else {
        return false;
    };
    if s.value == "href" && is_location_expr(&cme.object) {
        return true;
    }
    s.value == "location" && is_window_or_document(&cme.object)
}

fn is_location_expr(expr: &Expression) -> bool {
    match expr {
        Expression::Identifier(id) => id.name == "location",
        Expression::StaticMemberExpression(sme) => {
            sme.property.name == "location" && is_window_or_document(&sme.object)
        }
        Expression::ComputedMemberExpression(cme) => {
            let Expression::StringLiteral(s) = &cme.expression else {
                return false;
            };
            s.value == "location" && is_window_or_document(&cme.object)
        }
        _ => false,
    }
}

fn is_window_or_document(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::Identifier(id) if id.name == "window" || id.name == "document"
    )
}

fn is_location_call(callee: &Expression) -> bool {
    let (obj, name) = match callee {
        Expression::StaticMemberExpression(sme) => (&sme.object, sme.property.name.as_str()),
        Expression::ComputedMemberExpression(cme) => match &cme.expression {
            Expression::StringLiteral(s) => (&cme.object, s.value.as_str()),
            _ => return false,
        },
        _ => return false,
    };
    (name == "assign" || name == "replace") && is_location_expr(obj)
}

fn is_safe_url_value(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(s) => is_safe_url_str(&s.value),
        Expression::TemplateLiteral(tl) => tl
            .quasis
            .first()
            .is_some_and(|q| is_safe_url_str(q.value.cooked.as_deref().unwrap_or(&q.value.raw))),
        _ => false,
    }
}

fn is_safe_url_str(s: &str) -> bool {
    s.is_empty()
        || s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('#')
        || s.starts_with('?')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_location_href_variable() {
        let v = check("location.href = redirectUrl;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::OPEN_REDIRECT);
    }

    #[test]
    fn detects_location_replace() {
        let v = check("location.replace(url);", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_window_location_assign() {
        let v = check("window.location = target;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_string_literal() {
        assert!(check(r#"location.href = "/dashboard";"#, "/src/auth.ts").is_empty());
    }

    #[test]
    fn allows_relative_template() {
        assert!(check("location.href = `/users/${id}`;", "/src/auth.ts").is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check("// location.href = x;", "/src/auth.ts").is_empty());
    }

    #[test]
    fn detects_document_location() {
        assert_eq!(check("document.location = url;", "/src/auth.ts").len(), 1);
    }

    #[test]
    fn detects_document_location_href() {
        assert_eq!(
            check("document.location.href = url;", "/src/auth.ts").len(),
            1
        );
    }

    #[test]
    fn detects_location_assign() {
        assert_eq!(check("location.assign(url);", "/src/auth.ts").len(), 1);
    }

    #[test]
    fn ignores_relocation_href() {
        assert!(check("relocation.href = url;", "/src/auth.ts").is_empty());
    }

    #[test]
    fn detects_bracket_notation_href() {
        let v = check(r#"location["href"] = userInput;"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::OPEN_REDIRECT);
    }

    #[test]
    fn detects_bracket_notation_window_location() {
        let v = check(r#"window["location"] = target;"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_conditional_rhs() {
        let v = check(
            "location.href = isProd ? safePath : userInput;",
            "/src/auth.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_binary_rhs() {
        let v = check("location.href = baseUrl + path;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_hash_string() {
        assert!(check(r##"location.href = "#anchor";"##, "/src/auth.ts").is_empty());
    }

    #[test]
    fn allows_query_string() {
        assert!(check(r#"location.href = "?page=1";"#, "/src/auth.ts").is_empty());
    }

    #[test]
    fn allows_empty_string() {
        assert!(check(r#"location.href = "";"#, "/src/auth.ts").is_empty());
    }

    #[test]
    fn ignores_non_js_files() {
        assert!(check("location.href = url;", "/src/styles.css").is_empty());
    }

    #[test]
    fn fail_open_on_invalid_syntax() {
        assert!(check("function { invalid !!!", "/src/auth.ts").is_empty());
    }

    #[test]
    fn empty_file() {
        assert!(check("", "/src/auth.ts").is_empty());
    }
}
