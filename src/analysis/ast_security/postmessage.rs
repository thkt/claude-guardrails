use super::SecurityVisitor;
use crate::analysis::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, AssignmentTargetProperty, BindingPattern,
    CallExpression, ComputedMemberExpression, Expression, FormalParameters, FunctionBody, Program,
    StaticMemberExpression, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::Scoping;
use oxc_syntax::symbol::SymbolId;

impl SecurityVisitor<'_> {
    pub(super) fn check_postmessage_origin_missing(&mut self, call: &CallExpression<'_>) {
        let Some(handler) = message_listener_handler(call) else {
            return;
        };
        let Some((params, body)) = handler_signature_from_argument(handler) else {
            return;
        };
        let Some(first_param) = params.items.first() else {
            return;
        };
        if handler_validates_origin(&first_param.pattern, body, self.scoping) {
            return;
        }
        self.push_violation(
            rule_id::POSTMESSAGE_ORIGIN_MISSING,
            Severity::High,
            "Validate event.origin against an allowlist before handling postMessage. Drop messages from unexpected origins.",
            call.span,
        );
    }

    pub(super) fn check_onmessage_origin_missing(&mut self, expr: &AssignmentExpression<'_>) {
        let Some(handler) = message_assignment_handler(expr) else {
            return;
        };
        let Some((params, body)) = handler_signature_from_expression(handler) else {
            return;
        };
        let Some(first_param) = params.items.first() else {
            return;
        };
        if handler_validates_origin(&first_param.pattern, body, self.scoping) {
            return;
        }
        self.push_violation(
            rule_id::POSTMESSAGE_ORIGIN_MISSING,
            Severity::High,
            "Validate event.origin against an allowlist before handling postMessage. Drop messages from unexpected origins.",
            expr.span,
        );
    }
}

/// `window.addEventListener("message", handler)` / `self.…` / bare
/// `addEventListener("message", handler)` の handler 引数を返す。受信側 (window /
/// self / bare global) と event 名 "message" が揃わなければ None。
/// `check_postmessage_origin_missing` と `requires_semantic` の双方がこれを共有し、
/// pre-scan と本検査の検出条件が乖離しないようにする。
fn message_listener_handler<'a, 'b>(call: &'b CallExpression<'a>) -> Option<&'b Argument<'a>> {
    let callee_ok = match &call.callee {
        Expression::Identifier(id) => id.name == "addEventListener",
        Expression::StaticMemberExpression(sme) => {
            sme.property.name == "addEventListener"
                && matches!(
                    &sme.object,
                    Expression::Identifier(id) if matches!(id.name.as_str(), "window" | "self")
                )
        }
        _ => false,
    };
    if !callee_ok {
        return None;
    }
    let Some(Argument::StringLiteral(event_name)) = call.arguments.first() else {
        return None;
    };
    if event_name.value != "message" {
        return None;
    }
    call.arguments.get(1)
}

/// `window.onmessage = handler` / `self.…` / bare `onmessage = handler` の RHS を
/// 返す。受信側が一致しなければ None。`message_listener_handler` と同様、検出条件を
/// pre-scan と共有するための抽出。
fn message_assignment_handler<'a, 'b>(
    expr: &'b AssignmentExpression<'a>,
) -> Option<&'b Expression<'a>> {
    let receiver_ok = match &expr.left {
        AssignmentTarget::StaticMemberExpression(sme) => {
            sme.property.name == "onmessage"
                && (ast::is_ident(&sme.object, "window") || ast::is_ident(&sme.object, "self"))
        }
        AssignmentTarget::AssignmentTargetIdentifier(id) => id.name == "onmessage",
        _ => false,
    };
    receiver_ok.then_some(&expr.right)
}

/// `check_program` が `SemanticBuilder` を構築すべきか判定する。`scoping` を読むのは
/// identifier param を持つ message handler の origin チェックだけなので (#293)、
/// object-pattern handler や handler の無いファイルでは構築を skip する。
///
/// 検出は `message_listener_handler` / `message_assignment_handler` /
/// `handler_signature_*` を消費側と共有する。仮に乖離して under-detect しても
/// `scoping == None` → `handler_validates_origin` が false → violation が発火する
/// (安全な over-fire であり、抑制された finding にはならない)。
pub(super) fn requires_semantic(program: &Program) -> bool {
    let mut finder = IdentifierHandlerFinder { found: false };
    finder.visit_program(program);
    finder.found
}

struct IdentifierHandlerFinder {
    found: bool,
}

impl IdentifierHandlerFinder {
    /// handler の第1引数が `BindingIdentifier` (= scoping を読む唯一の形) なら
    /// `found` を立てる。object/array pattern や引数なしは scoping 不要。
    fn note_handler(&mut self, sig: Option<(&FormalParameters, &FunctionBody)>) {
        if let Some((params, _)) = sig {
            if matches!(
                params.items.first().map(|p| &p.pattern),
                Some(BindingPattern::BindingIdentifier(_))
            ) {
                self.found = true;
            }
        }
    }
}

impl<'a> Visit<'a> for IdentifierHandlerFinder {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found {
            return;
        }
        if let Some(handler) = message_listener_handler(call) {
            self.note_handler(handler_signature_from_argument(handler));
            if self.found {
                return;
            }
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
        if self.found {
            return;
        }
        if let Some(handler) = message_assignment_handler(expr) {
            self.note_handler(handler_signature_from_expression(handler));
            if self.found {
                return;
            }
        }
        walk::walk_assignment_expression(self, expr);
    }
}

/// Identifier param は body 内で `event.origin` を参照しているか。
/// `ObjectPattern` は param 段階で `origin` を取り出していれば検査経路ありとみなす。
/// その他 (`ArrayPattern`, rest 等) は経路なし扱いで保守的に fire。
fn handler_validates_origin<'a>(
    pat: &BindingPattern<'a>,
    body: &FunctionBody<'a>,
    scoping: Option<&Scoping>,
) -> bool {
    if let BindingPattern::BindingIdentifier(ident) = pat {
        // `symbol_id` is populated only by SemanticBuilder. It is `None` when
        // `check_program` skipped the build (no identifier-param handler
        // pre-scanned, see `requires_semantic`) or semantic could not resolve
        // the binding (parser failure etc.). Either way, treat as no reference
        // to stay conservative — the caller then fires (safe over-fire).
        let (Some(symbol_id), Some(scoping)) = (ident.symbol_id.get(), scoping) else {
            return false;
        };
        return has_origin_reference(body, symbol_id, scoping);
    }
    OriginReferenceFinder::pattern_destructures_origin(pat)
}

fn handler_signature_from_argument<'a, 'b>(
    arg: &'b Argument<'a>,
) -> Option<(&'b FormalParameters<'a>, &'b FunctionBody<'a>)> {
    match arg {
        Argument::ArrowFunctionExpression(arrow) => Some((&arrow.params, arrow.body.as_ref())),
        Argument::FunctionExpression(func) => {
            let body = func.body.as_deref()?;
            Some((&func.params, body))
        }
        _ => None,
    }
}

fn handler_signature_from_expression<'a, 'b>(
    expr: &'b Expression<'a>,
) -> Option<(&'b FormalParameters<'a>, &'b FunctionBody<'a>)> {
    match expr {
        Expression::ArrowFunctionExpression(arrow) => Some((&arrow.params, arrow.body.as_ref())),
        Expression::FunctionExpression(func) => {
            let body = func.body.as_deref()?;
            Some((&func.params, body))
        }
        _ => None,
    }
}

/// `event.origin` / `event["origin"]` / `const { origin } = event` /
/// `({ origin } = event)` のいずれかの形で param binding が `origin` プロパティへ
/// 触っているかを callback body 内で走査する。
fn has_origin_reference(
    body: &FunctionBody<'_>,
    param_symbol_id: SymbolId,
    scoping: &Scoping,
) -> bool {
    let mut finder = OriginReferenceFinder {
        param_symbol_id,
        scoping,
        found: false,
        clobbered: false,
    };
    finder.visit_function_body(body);
    finder.found
}

struct OriginReferenceFinder<'b> {
    param_symbol_id: SymbolId,
    scoping: &'b Scoping,
    found: bool,
    /// `var event = ...` は同じ `SymbolId` を function-scoped に再 bind する
    /// (`let`/`const` 同 scope は `SyntaxError` だが `oxc_semantic` は同じく
    /// 単一 symbol で resolve する)。以降の `event.origin` は attacker-
    /// controlled value を指すため、origin check として信用できない。
    clobbered: bool,
}

impl OriginReferenceFinder<'_> {
    /// `expr` が handler param と同一 symbol を指す identifier reference か。
    /// `oxc_semantic` の scope analysis に従い、inner で shadow された binding は
    /// 別 `SymbolId` を持つので自動的に false になる (nested function / arrow /
    /// block / destructuring rename を区別不要)。同 scope での `var` 再 bind は
    /// param symbol を reuse するため `clobbered` で無効化する。
    fn refers_to_param(&self, expr: &Expression) -> bool {
        if self.clobbered {
            return false;
        }
        let Expression::Identifier(id) = expr else {
            return false;
        };
        let Some(ref_id) = id.reference_id.get() else {
            return false;
        };
        self.scoping.get_reference(ref_id).symbol_id() == Some(self.param_symbol_id)
    }

    fn pattern_destructures_origin(pat: &BindingPattern) -> bool {
        let BindingPattern::ObjectPattern(obj) = pat else {
            return false;
        };
        obj.properties
            .iter()
            .any(|p| p.key.static_name().is_some_and(|n| n == "origin"))
    }

    fn target_destructures_origin(target: &AssignmentTarget) -> bool {
        let AssignmentTarget::ObjectAssignmentTarget(obj) = target else {
            return false;
        };
        obj.properties.iter().any(|p| match p {
            AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(id) => {
                id.binding.name == "origin"
            }
            AssignmentTargetProperty::AssignmentTargetPropertyProperty(prop) => {
                prop.name.static_name().is_some_and(|n| n == "origin")
            }
        })
    }
}

impl<'a> Visit<'a> for OriginReferenceFinder<'_> {
    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if self.found {
            return;
        }
        if it.property.name == "origin" && self.refers_to_param(&it.object) {
            self.found = true;
            return;
        }
        walk::walk_static_member_expression(self, it);
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        if self.found {
            return;
        }
        if let Expression::StringLiteral(s) = &it.expression {
            if s.value == "origin" && self.refers_to_param(&it.object) {
                self.found = true;
                return;
            }
        }
        walk::walk_computed_member_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if self.found {
            return;
        }
        if let BindingPattern::BindingIdentifier(ident) = &it.id {
            if ident.symbol_id.get() == Some(self.param_symbol_id) {
                self.clobbered = true;
                return;
            }
        }
        if let Some(init) = &it.init {
            if self.refers_to_param(init) && Self::pattern_destructures_origin(&it.id) {
                self.found = true;
                return;
            }
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if self.found {
            return;
        }
        if self.refers_to_param(&it.right) && Self::target_destructures_origin(&it.left) {
            self.found = true;
            return;
        }
        walk::walk_assignment_expression(self, it);
    }
}

#[cfg(test)]
mod tests;
