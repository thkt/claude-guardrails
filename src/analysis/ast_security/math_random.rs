use super::{name_matches_security_keyword, unwrap_parenthesized, SecurityVisitor};
use crate::analysis::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{
    Argument, BinaryOperator, BindingPattern, CallExpression, Expression, VariableDeclarator,
};

/// crypto API sink。当該 index に `Math.random()` が渡されると `Severity::High` で blocking する。
struct CryptoSink {
    object_aliases: &'static [&'static str],
    method: &'static str,
    crypto_arg_indices: &'static [usize],
}

const CRYPTO_SINK_METHODS: &[CryptoSink] = &[
    CryptoSink {
        object_aliases: &["bcrypt"],
        method: "hash",
        crypto_arg_indices: &[1],
    },
    CryptoSink {
        object_aliases: &["jsonwebtoken", "jwt"],
        method: "sign",
        crypto_arg_indices: &[1],
    },
    CryptoSink {
        object_aliases: &["crypto.subtle"],
        method: "importKey",
        crypto_arg_indices: &[1],
    },
    CryptoSink {
        object_aliases: &["crypto"],
        method: "createCipheriv",
        crypto_arg_indices: &[1, 2],
    },
    CryptoSink {
        object_aliases: &["crypto"],
        method: "createHmac",
        crypto_arg_indices: &[1],
    },
];

fn is_math_random_callee(call: &CallExpression) -> bool {
    let Expression::StaticMemberExpression(sme) = &call.callee else {
        return false;
    };
    ast::is_ident(&sme.object, "Math") && sme.property.name == "random"
}

fn is_math_random_call(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = unwrap_parenthesized(expr) else {
        return false;
    };
    is_math_random_callee(call)
}

fn member_object_chain(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(sme) => {
            let inner = member_object_chain(&sme.object)?;
            Some(format!("{}.{}", inner, sme.property.name))
        }
        _ => None,
    }
}

fn expression_contains_math_random(expr: &Expression) -> bool {
    let expr = unwrap_parenthesized(expr);
    if is_math_random_call(expr) {
        return true;
    }
    match expr {
        Expression::BinaryExpression(be) => {
            expression_contains_math_random(&be.left) || expression_contains_math_random(&be.right)
        }
        Expression::CallExpression(call) => {
            let callee_has = match &call.callee {
                Expression::StaticMemberExpression(sme) => {
                    expression_contains_math_random(&sme.object)
                }
                _ => false,
            };
            callee_has
                || call.arguments.iter().any(|a| {
                    a.as_expression()
                        .is_some_and(expression_contains_math_random)
                })
        }
        Expression::StaticMemberExpression(sme) => expression_contains_math_random(&sme.object),
        _ => false,
    }
}

/// `Math.random()` を「security 文脈で危険」と判定すべき右辺式かどうか。
/// 直接の呼び出し、`Math.floor/ceil/round` ラッパー内、または除算 (`/`) の被除数として
/// 含まれる場合は true。乗算 / 加算 jitter / 三項分岐 / JSX attribute は carve-out。
fn rhs_has_insecure_math_random(expr: &Expression) -> bool {
    if is_math_random_call(expr) {
        return true;
    }
    match expr {
        Expression::CallExpression(call) => {
            let Expression::StaticMemberExpression(sme) = &call.callee else {
                return false;
            };
            if !ast::is_ident(&sme.object, "Math") {
                return false;
            }
            if !matches!(sme.property.name.as_str(), "floor" | "ceil" | "round") {
                return false;
            }
            call.arguments.iter().any(|a| {
                a.as_expression()
                    .is_some_and(expression_contains_math_random)
            })
        }
        Expression::BinaryExpression(be) if be.operator == BinaryOperator::Division => {
            expression_contains_math_random(&be.left)
        }
        _ => false,
    }
}

impl SecurityVisitor<'_> {
    pub(super) fn check_math_random_insecure(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Expression::StaticMemberExpression(method) = &call.callee else {
            return;
        };
        if method.property.name != "toString" {
            return;
        }
        let [arg] = call.arguments.as_slice() else {
            return;
        };
        let Argument::NumericLiteral(n) = arg else {
            return;
        };
        if (n.value - 36.0).abs() > f64::EPSILON {
            return;
        }
        let Expression::CallExpression(inner) = &method.object else {
            return;
        };
        if !is_math_random_callee(inner) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::High,
            "Math.random() is not cryptographically secure. Use crypto.randomBytes() for tokens/IDs.",
            call.span,
        );
    }

    pub(super) fn check_math_random_crypto_sink(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Some((obj, method)) = ast::member_name(&call.callee) else {
            return;
        };
        // method 名が CRYPTO_SINK_METHODS のどれにも一致しない CallExpression が大多数なので、
        // String を生成する member_object_chain より先に method 名で zero-cost filter する。
        if !CRYPTO_SINK_METHODS.iter().any(|s| s.method == method) {
            return;
        }
        let Some(chain) = member_object_chain(obj) else {
            return;
        };
        for sink in CRYPTO_SINK_METHODS {
            if sink.method != method {
                continue;
            }
            if !sink.object_aliases.contains(&chain.as_str()) {
                continue;
            }
            for &i in sink.crypto_arg_indices {
                if let Some(expr) = call.arguments.get(i).and_then(|a| a.as_expression()) {
                    if expression_contains_math_random(expr) {
                        self.push_violation(
                            rule_id::MATH_RANDOM_INSECURE,
                            Severity::High,
                            "Math.random() is not cryptographically secure as crypto API input. Use crypto.randomBytes() or crypto.getRandomValues().",
                            call.span,
                        );
                        return;
                    }
                }
            }
        }
    }

    pub(super) fn check_math_random_keyword_var(&mut self, decl: &VariableDeclarator) {
        if self.is_test_file {
            return;
        }
        let BindingPattern::BindingIdentifier(ident) = &decl.id else {
            return;
        };
        if !name_matches_security_keyword(&ident.name) {
            return;
        }
        let Some(init) = &decl.init else {
            return;
        };
        if !rhs_has_insecure_math_random(init) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random() assigned to a security-named variable. Use crypto.randomBytes() or crypto.getRandomValues() for tokens/IDs.",
            decl.span,
        );
    }

    pub(super) fn check_math_random_keyword_fn(&mut self, call: &CallExpression) {
        if self.is_test_file || !self.in_security_named_fn {
            return;
        }
        if !is_math_random_callee(call) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random() inside a security-named function. Use crypto.randomBytes() or crypto.getRandomValues() for tokens/IDs.",
            call.span,
        );
    }

    pub(super) fn check_math_random_to_string_other(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Expression::StaticMemberExpression(method) = &call.callee else {
            return;
        };
        match method.property.name.as_str() {
            // `toString(36)` は check_math_random_insecure が High で扱う。
            // ここでは radix 36 のみ除外し、それ以外の toString() / toFixed() を Medium に。
            "toString" => {
                if let [Argument::NumericLiteral(n)] = call.arguments.as_slice() {
                    if (n.value - 36.0).abs() <= f64::EPSILON {
                        return;
                    }
                }
            }
            "toFixed" => {}
            _ => return,
        }
        let Expression::CallExpression(inner) = &method.object else {
            return;
        };
        if !is_math_random_callee(inner) {
            return;
        }
        self.push_violation(
            rule_id::MATH_RANDOM_INSECURE,
            Severity::Medium,
            "Math.random().toString()/toFixed() in a likely identifier context. Use crypto.randomBytes() or crypto.getRandomValues() for tokens/IDs.",
            call.span,
        );
    }
}

#[cfg(test)]
mod tests;
