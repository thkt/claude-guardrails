use super::SecurityVisitor;
use crate::analysis::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, BinaryOperator, CallExpression, Expression,
};

impl SecurityVisitor<'_> {
    pub(super) fn check_html_assignment(&mut self, expr: &AssignmentExpression) {
        let Some(property) = assignment_target_property(&expr.left) else {
            return;
        };
        let (severity, fix) = match property {
            "innerHTML" => (
                Severity::High,
                "Use el.textContent = x for plain text, or el.innerHTML = DOMPurify.sanitize(x) when HTML is required",
            ),
            "outerHTML" => (
                Severity::Medium,
                "Use el.replaceWith(node) or el.outerHTML = DOMPurify.sanitize(html) instead of raw outerHTML assignment",
            ),
            _ => return,
        };
        if is_safe_html_value(&expr.right) {
            return;
        }
        self.push_violation(rule_id::UNSAFE_HTML_INJECTION, severity, fix, expr.span);
    }

    pub(super) fn check_document_write(&mut self, call: &CallExpression) {
        let Expression::StaticMemberExpression(sme) = &call.callee else {
            return;
        };
        if !matches!(sme.property.name.as_str(), "write" | "writeln") {
            return;
        }
        if !ast::is_ident(&sme.object, "document") {
            return;
        }
        if call
            .arguments
            .first()
            .and_then(|a| a.as_expression())
            .is_some_and(is_safe_html_value)
        {
            return;
        }
        self.push_violation(
            rule_id::UNSAFE_HTML_INJECTION,
            Severity::High,
            "Use document.createElement(tag) + parent.appendChild(el) instead of document.write()",
            call.span,
        );
    }
}

/// The assigned property name for `el.innerHTML = x` and `el["innerHTML"] = x`.
/// Only a string-literal computed key resolves — a dynamic key (`el[prop] = x`)
/// is not a statically known HTML sink, so it returns `None` (FN-2 #377).
fn assignment_target_property<'a>(target: &'a AssignmentTarget) -> Option<&'a str> {
    match target {
        AssignmentTarget::StaticMemberExpression(sme) => Some(sme.property.name.as_str()),
        AssignmentTarget::ComputedMemberExpression(cme) => match &cme.expression {
            Expression::StringLiteral(s) => Some(s.value.as_str()),
            _ => None,
        },
        _ => None,
    }
}

fn is_safe_html_value(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) => true,
        _ if ast::is_static_template_literal(expr) => true,
        Expression::BinaryExpression(be) => {
            matches!(be.operator, BinaryOperator::Addition)
                && is_safe_html_value(&be.left)
                && is_safe_html_value(&be.right)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
