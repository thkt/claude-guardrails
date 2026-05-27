use super::SecurityVisitor;
use crate::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, BinaryOperator, CallExpression, Expression,
};

impl SecurityVisitor<'_> {
    pub(super) fn check_html_assignment(&mut self, expr: &AssignmentExpression) {
        let AssignmentTarget::StaticMemberExpression(sme) = &expr.left else {
            return;
        };
        let (severity, fix) = match sme.property.name.as_str() {
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
