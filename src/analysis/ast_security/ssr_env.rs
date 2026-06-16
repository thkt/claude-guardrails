use super::{ascii_fold_underscore_contains, unwrap_parenthesized, SecurityVisitor};
use crate::analysis::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{
    Expression, LogicalExpression, LogicalOperator, ObjectPropertyKind, ReturnStatement,
    StaticMemberExpression,
};

// SECRET_KEY / SESSION_SECRET 等は SECRET の substring match で網羅される。
// KEY 単体は PUBLIC_KEY / SORT_KEY 等を誤検知するため除外し API_KEY のみ採用。
const SENSITIVE_ENV_KEYWORDS: [&str; 6] = [
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "JWT",
    "CREDENTIAL",
];

const NEXT_PUBLIC_PREFIX: &str = "NEXT_PUBLIC_";

// NODE_ENV は React / Next.js / Webpack が client bundle に compile-time embed する
// 公式 public 値で、`process.env.NODE_ENV === 'production'` 形式の dev/prod 分岐は
// 一般的。NEXT_PUBLIC_ prefix と並ぶ allow 対象として明示する。
const CLIENT_ENV_ALLOW_LIST: [&str; 1] = ["NODE_ENV"];

// Underscore-free lowercase needles paired with `ascii_fold_underscore_contains`
// so `apiKey`, `API_KEY`, `db_token` all match the same `apikey` / `token` entry.
// Kept separate from `SENSITIVE_ENV_KEYWORDS` (used on the SCREAMING_SNAKE value
// side via plain `contains`) so each side can evolve independently.
const SSR_SECRET_KEYWORDS: [&str; 6] =
    ["secret", "token", "password", "apikey", "jwt", "credential"];

/// Return true when `name`, ASCII-lowercase folded and with `_` removed, contains any
/// `SSR_SECRET_KEYWORDS` entry as a substring. Targets SSR return-object property names
/// (`apiKey`, `API_KEY`, `db_token`, `password`, …) across camelCase, `snake_case` and
/// `SCREAMING_SNAKE` forms.
fn name_matches_ssr_secret_keyword(name: &str) -> bool {
    let bytes = name.as_bytes();
    SSR_SECRET_KEYWORDS
        .iter()
        .any(|kw| ascii_fold_underscore_contains(bytes, kw.as_bytes()))
}

impl SecurityVisitor<'_> {
    // Flags `process.env.X || "literal"` and left-associated multi-stage env
    // chains ending in a string literal (see #295). Identifier-bound fallbacks
    // are intentionally skipped so the violation message cannot double as a
    // bypass hint.
    pub(super) fn check_env_var_fallback(&mut self, expr: &LogicalExpression) {
        if !matches!(
            expr.operator,
            LogicalOperator::Coalesce | LogicalOperator::Or
        ) {
            return;
        }
        let Expression::StringLiteral(s) = &expr.right else {
            return;
        };
        if s.value.is_empty() {
            return;
        }
        // The literal fallback only takes effect as the chain's last operand,
        // so the sensitive env access may sit anywhere in the left chain. For the
        // primary `env || env || "lit"` shape the inner `env || env` node has a
        // non-literal right operand and bails above, so it fires exactly once.
        // intentional: the degenerate `env || "x" || "y"` (literals mid-chain)
        // fires once per node since each is an independent true positive; the
        // shape is rare and deduping would need parent tracking (rejected, #295).
        if !chain_contains_sensitive_env(&expr.left) {
            return;
        }
        self.push_violation(
            rule_id::ENV_VAR_FALLBACK,
            Severity::High,
            "Throw an error when required env var is missing. Never fall back to a hardcoded secret.",
            expr.span,
        );
    }

    pub(super) fn check_client_env_public_leak(&mut self, sme: &StaticMemberExpression) {
        if !self.has_use_client {
            return;
        }
        if self.use_server_depth > 0 {
            return;
        }
        let Some(name) = process_env_access_name_from_sme(sme) else {
            return;
        };
        if name.starts_with(NEXT_PUBLIC_PREFIX) {
            return;
        }
        if CLIENT_ENV_ALLOW_LIST.contains(&name) {
            return;
        }
        self.push_violation(
            rule_id::CLIENT_ENV_PUBLIC_LEAK,
            Severity::High,
            "process.env in a 'use client' module is bundled to the browser. Move to a server component, or use a NEXT_PUBLIC_ prefix if the value is public.",
            sme.span,
        );
    }

    pub(super) fn check_ssr_secret_bleed_return(&mut self, stmt: &ReturnStatement) {
        if !self.in_direct_ssr_target {
            return;
        }
        let Some(arg) = &stmt.argument else {
            return;
        };
        self.check_ssr_secret_object(arg);
    }

    /// Walk an SSR return value: for each direct property of an `ObjectExpression`,
    /// flag secret-named keys, flag `process.env.<SECRET>` values, otherwise recurse
    /// into nested object literals (so `{ props: { user: { token: ... } } }` and any
    /// other depth is reached). Non-object values and spread elements are skipped;
    /// variable-bound returns never reach here.
    pub(super) fn check_ssr_secret_object(&mut self, expr: &Expression) {
        let expr = unwrap_parenthesized(expr);
        let Expression::ObjectExpression(obj) = expr else {
            return;
        };
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(op) = prop else {
                continue;
            };
            let Some(key_name) = op.key.static_name() else {
                continue;
            };
            if name_matches_ssr_secret_keyword(&key_name) {
                self.push_violation(
                    rule_id::SSR_SECRET_BLEED,
                    Severity::High,
                    "SSR/Server Action return is sent to the client. Move secret-named field server-side or rename if value is public.",
                    op.span,
                );
                continue;
            }
            if is_sensitive_env_access(&op.value) {
                self.push_violation(
                    rule_id::SSR_SECRET_BLEED,
                    Severity::High,
                    "SSR/Server Action return is sent to the client. process.env secret leaks to the browser; return only render-needed data.",
                    op.span,
                );
                continue;
            }
            self.check_ssr_secret_object(&op.value);
        }
    }
}

/// True when `expr` is a `process.env.<SENSITIVE>` access, or a `||`/`??` chain
/// any of whose operands is one. Recurses the left-leaning spine so a multi-stage
/// fallback like `process.env.SECRET || process.env.ALT || "lit"` is reached even
/// though its outer left operand is itself a `LogicalExpression` (see #295).
fn chain_contains_sensitive_env(expr: &Expression) -> bool {
    match unwrap_parenthesized(expr) {
        Expression::LogicalExpression(le)
            if matches!(le.operator, LogicalOperator::Coalesce | LogicalOperator::Or) =>
        {
            chain_contains_sensitive_env(&le.left) || chain_contains_sensitive_env(&le.right)
        }
        other => is_sensitive_env_access(other),
    }
}

fn is_sensitive_env_access(expr: &Expression) -> bool {
    process_env_access_name(expr)
        .is_some_and(|name| SENSITIVE_ENV_KEYWORDS.iter().any(|kw| name.contains(kw)))
}

fn process_env_access_name<'a>(expr: &'a Expression) -> Option<&'a str> {
    let Expression::StaticMemberExpression(outer) = expr else {
        return None;
    };
    process_env_access_name_from_sme(outer)
}

fn process_env_access_name_from_sme<'a>(outer: &'a StaticMemberExpression) -> Option<&'a str> {
    let Expression::StaticMemberExpression(inner) = &outer.object else {
        return None;
    };
    if !ast::is_ident(&inner.object, "process") || inner.property.name != "env" {
        return None;
    }
    Some(outer.property.name.as_str())
}

#[cfg(test)]
mod tests;
