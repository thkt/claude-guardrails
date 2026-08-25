use super::{rule_id, Severity, Violation, RE_JS_FILE};
use crate::analysis::ast;
use oxc_ast::ast::{AssignmentExpression, AssignmentTarget, CallExpression, Expression, Program};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

const FIX_MESSAGE: &str = "Open redirect risk. Validate against an allowlist before redirect (e.g., if (!ALLOWED_PATHS.includes(url)) return).";

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    super::test_check_program(content, file_path, check_program)
}

#[cfg(test)]
fn check_fail_open(content: &str, file_path: &str) -> Vec<Violation> {
    super::test_check_program_fail_open(content, file_path, check_program)
}

pub(crate) fn check_program(
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
            origin: None,
            no_demote: None,
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
        AssignmentTarget::StaticMemberExpression(sme) => {
            matches_location_member(&sme.object, sme.property.name.as_str())
        }
        AssignmentTarget::ComputedMemberExpression(cme) => ast::static_key(&cme.expression)
            .is_some_and(|name| matches_location_member(&cme.object, name)),
        _ => false,
    }
}

fn matches_location_member(obj: &Expression, name: &str) -> bool {
    match name {
        "href" => is_location_expr(obj),
        "location" => is_window_or_document(obj),
        _ => false,
    }
}

fn is_location_expr(expr: &Expression) -> bool {
    if ast::is_ident(expr, "location") {
        return true;
    }
    ast::member_name(expr)
        .is_some_and(|(obj, name)| name == "location" && is_window_or_document(obj))
}

fn is_window_or_document(expr: &Expression) -> bool {
    ast::is_ident(expr, "window") || ast::is_ident(expr, "document")
}

fn is_location_call(callee: &Expression) -> bool {
    ast::member_name(callee)
        .is_some_and(|(obj, name)| matches!(name, "assign" | "replace") && is_location_expr(obj))
}

fn is_safe_url_value(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(s) => is_safe_url_str(&s.value),
        // Template is safe when its literal prefix already commits to a relative URL.
        // With expressions, the leading quasi must be non-empty so interpolations cannot
        // supply scheme/host (e.g., `${url}` must be flagged).
        Expression::TemplateLiteral(tl) => tl.quasis.first().is_some_and(|q| {
            let s = q.value.cooked.as_deref().unwrap_or(&q.value.raw);
            if tl.expressions.is_empty() {
                is_safe_url_str(s)
            } else {
                !s.is_empty() && is_safe_url_str(s)
            }
        }),
        _ => false,
    }
}

fn is_safe_url_str(s: &str) -> bool {
    if s.starts_with("//") {
        return false;
    }
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
    fn detects_window_location_property_assignment() {
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

    // T-383-8 (#383): a substitution-free template-literal computed key resolves
    // like the string-literal form; the assignment target arm previously matched
    // only StringLiteral, leaving `location[`href`] = x` an undetected redirect.
    #[test]
    fn detects_template_key_href() {
        let v = check("location[`href`] = userInput;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::OPEN_REDIRECT);
    }

    #[test]
    fn ignores_template_key_non_location_member() {
        assert!(check("location[`pathname`] = userInput;", "/src/auth.ts").is_empty());
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
    fn detects_empty_quasi_template() {
        let v = check("location.href = `${userInput}`;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::OPEN_REDIRECT);
    }

    #[test]
    fn detects_protocol_relative_string() {
        let v = check(r#"location.href = "//evil.com";"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::OPEN_REDIRECT);
    }

    #[test]
    fn detects_protocol_relative_template() {
        let v = check("location.href = `//${host}`;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_static_template_no_expressions() {
        assert!(check("location.href = `/dashboard`;", "/src/auth.ts").is_empty());
    }

    #[test]
    fn ignores_non_js_files() {
        assert!(check_fail_open("location.href = url;", "/src/styles.css").is_empty());
    }

    #[test]
    fn fail_open_on_invalid_syntax() {
        assert!(check_fail_open("function { invalid !!!", "/src/auth.ts").is_empty());
    }

    #[test]
    fn empty_file() {
        assert!(check("", "/src/auth.ts").is_empty());
    }

    #[test]
    fn fix_message_includes_concrete_snippet() {
        let v = check("location.href = redirectUrl;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert!(
            v[0].fix.contains("allowlist"),
            "fix lacks allowlist anchor: {}",
            v[0].fix
        );
        assert!(
            v[0].fix.contains("includes(url)"),
            "fix lacks code snippet anchor: {}",
            v[0].fix
        );
    }
}
