//! `test-endpoint-prod-guard` (Issue #358): warn when a Next.js file-based
//! route whose path names a test segment (`test` / `seed` / `dev` / `debug` /
//! `fixture`) carries no in-file production guard.
//!
//! Scope is deliberately narrow because a single file's AST cannot prove a guard
//! exists or is absent in the general case:
//! - String-argument routers (Express `app.get('/api/test', …)`, Hono) name the
//!   route in an arbitrary file's call argument, so the route cannot be identified
//!   from the path alone. Out of scope.
//! - Guards living in `middleware.ts`, a build/env exclusion, or any other file
//!   need cross-file resolution the `PreToolUse` single-file hook cannot do. Their
//!   absence here is a false negative we accept (advisory, fail-open direction).
//!
//! Detection is therefore a whole-file presence check: any `process.env.NODE_ENV`
//! compared against the string `"production"` (`===` / `!==` / `==` / `!=`) counts
//! as a guard, wherever in the AST it appears — `if` test, ternary, or a
//! `const isProd = …` binding all qualify, since [`is_node_env_prod_comparison`]
//! matches the comparison node itself, not the surrounding statement shape.
//!
//! Accepted in-file blind spots of that presence model (advisory rule, so each is a
//! soft miss, not a wrong block):
//! - A comparison that exists but does not gate the handler (e.g. logged, not
//!   returned/thrown) still silences the warning — proving a comparison *gates*
//!   needs control-flow analysis this rule deliberately omits. False negative.
//! - `process.env['NODE_ENV']` bracket access and a `` `production` `` template
//!   literal are not recognized as the guard form, so a route guarded only that way
//!   is still warned. False positive against the dominant `=== 'production'` idiom.

use super::SecurityVisitor;
use crate::analysis::ast;
use crate::rules::{rule_id, Severity, Violation};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression};

const NODE_ENV: &str = "NODE_ENV";
const PRODUCTION: &str = "production";

/// True when `expr` compares `process.env.NODE_ENV` against the string literal
/// `"production"` with an equality operator (either operand order). This is the
/// guard-presence signal: forms A (`=== 'production'` early return) and B
/// (`!== 'production'` inverted) both contain such a node, as do ternary and
/// variable-bound guards.
pub(super) fn is_node_env_prod_comparison(expr: &BinaryExpression) -> bool {
    if !matches!(
        expr.operator,
        BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
            | BinaryOperator::Equality
            | BinaryOperator::Inequality
    ) {
        return false;
    }
    let (left, right) = (&expr.left, &expr.right);
    (is_node_env_access(left) && is_production_literal(right))
        || (is_node_env_access(right) && is_production_literal(left))
}

/// `process.env.NODE_ENV` member access.
fn is_node_env_access(expr: &Expression) -> bool {
    let Expression::StaticMemberExpression(outer) = expr else {
        return false;
    };
    if outer.property.name != NODE_ENV {
        return false;
    }
    let Expression::StaticMemberExpression(inner) = &outer.object else {
        return false;
    };
    ast::is_ident(&inner.object, "process") && inner.property.name == "env"
}

fn is_production_literal(expr: &Expression) -> bool {
    matches!(expr, Expression::StringLiteral(s) if s.value == PRODUCTION)
}

impl SecurityVisitor<'_> {
    /// Records that a production guard exists somewhere in the file. Called from
    /// `visit_binary_expression`; the absence verdict is emitted post-walk by
    /// [`emit_if_unguarded`] so the whole file is seen before deciding.
    pub(super) fn note_prod_guard(&mut self, expr: &BinaryExpression) {
        if self.is_test_route && is_node_env_prod_comparison(expr) {
            self.prod_env_guard_seen = true;
        }
    }
}

/// Push the advisory violation when a test route was visited with no production
/// guard found. Anchored at line 1 because the finding is an absence, not a node.
pub(super) fn emit_if_unguarded(visitor: &mut SecurityVisitor) {
    if visitor.is_test_route && !visitor.prod_env_guard_seen {
        visitor.violations.push(Violation {
            rule: rule_id::TEST_ENDPOINT_PROD_GUARD.to_owned(),
            severity: Severity::Medium,
            fix: "Test-only route has no production guard. Add `if (process.env.NODE_ENV === 'production') return new Response('Not found', { status: 404 })`, or confirm the route is excluded from production another way."
                .to_owned(),
            file: visitor.file_path.to_owned(),
            line: Some(1),
            origin: None,
        });
    }
}

#[cfg(test)]
mod tests;
