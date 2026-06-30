use super::SecurityVisitor;
use crate::analysis::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, BinaryOperator, CallExpression, Expression,
    ImportDeclarationSpecifier, ObjectPropertyKind, Program, Statement,
};
use std::collections::HashSet;

const CHILD_PROCESS_FNS: [&str; 4] = ["exec", "execSync", "spawn", "spawnSync"];

// Modules whose named exports are the Node child-process API. A bare call like
// `exec(x)` fires source-agnostically (the canonical name is signal enough), but
// an arbitrary local alias (`run`) carries no such prior, so alias resolution is
// restricted to these sources to keep precision: `import { exec as run } from
// './db'` must not fire CHILD_PROCESS_INJECTION.
const CHILD_PROCESS_MODULES: [&str; 2] = ["child_process", "node:child_process"];

/// Collect the local names that `import { <cp-fn> as <local> }` binds from a
/// child-process module, so a later call to `<local>(dynamicArg)` resolves back
/// to the child-process API. Only true renames are recorded; a non-aliased
/// `import { exec }` is already matched by the bare-name path.
pub(super) fn collect_cp_named_aliases(program: &Program) -> HashSet<String> {
    let mut aliases = HashSet::new();
    for stmt in &program.body {
        let Statement::ImportDeclaration(decl) = stmt else {
            continue;
        };
        if !CHILD_PROCESS_MODULES.contains(&decl.source.value.as_str()) {
            continue;
        }
        let Some(specifiers) = &decl.specifiers else {
            continue;
        };
        for spec in specifiers {
            let ImportDeclarationSpecifier::ImportSpecifier(s) = spec else {
                continue;
            };
            let imported = s.imported.name();
            if CHILD_PROCESS_FNS.contains(&imported.as_str()) && s.local.name.as_str() != imported {
                aliases.insert(s.local.name.to_string());
            }
        }
    }
    aliases
}

impl SecurityVisitor<'_> {
    pub(super) fn check_err_stack(&mut self, call: &CallExpression) {
        if !self.is_api_or_route {
            return;
        }
        if !is_response_call(&call.callee) {
            return;
        }
        for arg in &call.arguments {
            if arg_contains_stack(arg) {
                self.push_violation(
                    rule_id::ERR_STACK_EXPOSURE,
                    Severity::High,
                    "Use generic error message in production. Log stack trace server-side.",
                    call.span,
                );
                return;
            }
        }
    }

    pub(super) fn check_child_process(&mut self, call: &CallExpression) {
        if !self.in_server_context() {
            return;
        }
        // Named-import aliases (`import { exec as run }`) resolve via the
        // child-process alias set built in collect_cp_named_aliases. Namespace
        // (`import * as cp`) and default imports are not resolved here: a
        // `cp.exec(x)` member call already matches by property name below, so the
        // remaining gap is only a default/namespace binding renamed away from a
        // bare child-process function name.
        let is_child_process = match &call.callee {
            Expression::Identifier(id) => {
                CHILD_PROCESS_FNS.contains(&id.name.as_str())
                    || self.cp_named_aliases.contains(id.name.as_str())
            }
            Expression::StaticMemberExpression(sme) => {
                CHILD_PROCESS_FNS.contains(&sme.property.name.as_str())
            }
            Expression::ComputedMemberExpression(cme) => {
                ast::static_key(&cme.expression).is_some_and(|key| CHILD_PROCESS_FNS.contains(&key))
            }
            _ => return,
        };
        if !is_child_process {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_string_literal_arg(first) {
            self.push_violation(
                rule_id::CHILD_PROCESS_INJECTION,
                Severity::High,
                "Use string literal for command. Validate and sanitize dynamic input.",
                call.span,
            );
        }
    }

    pub(super) fn check_fs_path(&mut self, call: &CallExpression) {
        if !self.in_server_context() {
            return;
        }
        let obj = match &call.callee {
            Expression::StaticMemberExpression(sme) => &sme.object,
            // Still-open gap: only a binding literally named `fs` is matched. A
            // default or namespace import renamed away from `fs` (e.g. `import f
            // from 'node:fs'; f.readFile(x)`) needs the module binding resolved,
            // which the named-import alias set does not cover.
            Expression::ComputedMemberExpression(cme) => match ast::static_key(&cme.expression) {
                Some(_) => &cme.object,
                None => return,
            },
            _ => return,
        };
        if !ast::is_ident(obj, "fs") {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_safe_path_arg(first) {
            self.push_violation(
                rule_id::NON_LITERAL_FS_PATH,
                Severity::Medium,
                "Use string literal for file path. Validate against path traversal.",
                call.span,
            );
        }
    }

    pub(super) fn check_non_literal_require(&mut self, call: &CallExpression) {
        if !self.in_server_context() {
            return;
        }
        let Expression::Identifier(id) = &call.callee else {
            return;
        };
        if id.name != "require" {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_string_literal_arg(first) {
            self.push_violation(
                rule_id::NON_LITERAL_REQUIRE,
                Severity::Medium,
                "Use string literal for require(). Dynamic require allows arbitrary code loading.",
                call.span,
            );
        }
    }
}

fn is_response_call(callee: &Expression) -> bool {
    let (object, method) = match callee {
        Expression::StaticMemberExpression(sme) => (&sme.object, sme.property.name.as_str()),
        Expression::ComputedMemberExpression(cme) => match ast::static_key(&cme.expression) {
            Some(key) => (&cme.object, key),
            None => return false,
        },
        _ => return false,
    };
    if method != "json" && method != "send" {
        return false;
    }
    if ast::is_ident(object, "res") || ast::is_ident(object, "response") {
        return true;
    }
    let Expression::CallExpression(inner) = object else {
        return false;
    };
    let Expression::StaticMemberExpression(inner_sme) = &inner.callee else {
        return false;
    };
    inner_sme.property.name == "status"
        && (ast::is_ident(&inner_sme.object, "res") || ast::is_ident(&inner_sme.object, "response"))
}

fn arg_contains_stack(arg: &Argument) -> bool {
    match arg {
        Argument::SpreadElement(s) => spread_contains_stack(&s.argument),
        _ => arg.as_expression().is_some_and(|e| expr_contains_stack(e)),
    }
}

/// Spread of a bare identifier (e.g., `...err`) may copy a `.stack` property;
/// treat as unsafe in spread context only.
fn spread_contains_stack(expr: &Expression) -> bool {
    matches!(expr, Expression::Identifier(_)) || expr_contains_stack(expr)
}

fn expr_contains_stack(expr: &Expression) -> bool {
    match expr {
        Expression::StaticMemberExpression(sme) => {
            sme.property.name == "stack" || expr_contains_stack(&sme.object)
        }
        Expression::ObjectExpression(obj) => obj.properties.iter().any(|p| match p {
            ObjectPropertyKind::ObjectProperty(op) => expr_contains_stack(&op.value),
            ObjectPropertyKind::SpreadProperty(sp) => spread_contains_stack(&sp.argument),
        }),
        Expression::CallExpression(call) => call.arguments.iter().any(|a| arg_contains_stack(a)),
        Expression::ConditionalExpression(ce) => {
            expr_contains_stack(&ce.consequent) || expr_contains_stack(&ce.alternate)
        }
        Expression::LogicalExpression(le) => {
            expr_contains_stack(&le.left) || expr_contains_stack(&le.right)
        }
        Expression::ArrayExpression(arr) => arr.elements.iter().any(|el| match el {
            ArrayExpressionElement::SpreadElement(s) => spread_contains_stack(&s.argument),
            ArrayExpressionElement::Elision(_) => false,
            _ => el.as_expression().is_some_and(expr_contains_stack),
        }),
        Expression::TemplateLiteral(tl) => tl.expressions.iter().any(|e| expr_contains_stack(e)),
        _ => false,
    }
}

fn is_string_literal_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg
            .as_expression()
            .is_some_and(ast::is_static_template_literal),
    }
}

fn is_safe_path_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg.as_expression().is_some_and(is_static_path),
    }
}

fn is_static_path(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) => true,
        _ if ast::is_static_template_literal(expr) => true,
        Expression::Identifier(id) => id.name == "__dirname" || id.name == "__filename",
        Expression::BinaryExpression(be) => {
            matches!(be.operator, BinaryOperator::Addition)
                && is_static_path(&be.left)
                && is_static_path(&be.right)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
