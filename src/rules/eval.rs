use super::{rule_id, Severity, Violation, RE_JS_FILE};
use crate::analysis::ast;
use crate::import_map::{ImportKind, ImportMap};
use oxc_ast::ast::{CallExpression, Expression, NewExpression, Program};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Eval,
    Function,
}

impl Target {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "eval" => Some(Target::Eval),
            "Function" => Some(Target::Function),
            _ => None,
        }
    }

    fn fix(self) -> &'static str {
        match self {
            Target::Eval => "Avoid eval(). Use JSON.parse() for data or safe alternatives.",
            Target::Function => {
                "Avoid dynamic code generation with Function(). Use static functions."
            }
        }
    }
}

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    super::ast_test_check(content, file_path, |program, line_offsets| {
        let import_map = ImportMap::build(program);
        check_program(program, line_offsets, file_path, &import_map)
    })
}

#[cfg(test)]
fn check_fail_open(content: &str, file_path: &str) -> Vec<Violation> {
    super::ast_fail_open_check(content, file_path, |program, line_offsets| {
        let import_map = ImportMap::build(program);
        check_program(program, line_offsets, file_path, &import_map)
    })
}

pub(crate) fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
    import_map: &ImportMap,
) -> Vec<Violation> {
    if !RE_JS_FILE.is_match(file_path) {
        return Vec::new();
    }
    let mut visitor = EvalVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets,
        import_map,
    };
    visitor.visit_program(program);
    visitor.violations
}

struct EvalVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
    import_map: &'s ImportMap,
}

impl EvalVisitor<'_> {
    fn span_to_line(&self, span: Span) -> u32 {
        ast::span_to_line(self.line_offsets, span)
    }

    fn push(&mut self, target: Target, span: Span) {
        self.violations.push(Violation {
            rule: rule_id::EVAL.to_owned(),
            severity: Severity::High,
            fix: target.fix().to_owned(),
            file: self.file_path.to_owned(),
            line: Some(self.span_to_line(span)),
            origin: None,
            no_demote: None,
        });
    }

    fn resolve_target(&self, callee: &Expression) -> Option<Target> {
        if let Expression::Identifier(id) = callee {
            return self.resolve_local(id.name.as_str());
        }
        let (object, method) = ast::member_name(callee)?;
        self.resolve_member(object, method)
    }

    fn resolve_local(&self, name: &str) -> Option<Target> {
        if let Some(t) = Target::from_name(name) {
            return Some(t);
        }
        let entry = self.import_map.resolve(name)?;
        if entry.kind != ImportKind::Named {
            return None;
        }
        Target::from_name(entry.original_name.as_str())
    }

    fn resolve_member(&self, object: &Expression, method: &str) -> Option<Target> {
        let target = Target::from_name(method)?;
        let Expression::Identifier(id) = object else {
            return None;
        };
        if matches!(id.name.as_str(), "window" | "globalThis") {
            return Some(target);
        }
        let entry = self.import_map.resolve(id.name.as_str())?;
        if entry.kind != ImportKind::Namespace {
            return None;
        }
        Some(target)
    }
}

impl<'a> Visit<'a> for EvalVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(target) = self.resolve_target(&call.callee) {
            self.push(target, call.span);
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, expr: &NewExpression<'a>) {
        if let Some(Target::Function) = self.resolve_target(&expr.callee) {
            self.push(Target::Function, expr.span);
        }
        walk::walk_new_expression(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_js(code: &str) -> Vec<Violation> {
        check(code, "/src/app.ts")
    }

    #[test]
    fn detects_eval_call() {
        let v = check_js("eval(userInput);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::EVAL);
    }

    #[test]
    fn detects_new_function() {
        let v = check_js(r#"new Function("return " + x);"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    #[test]
    fn detects_bare_function_constructor() {
        let v = check_js(r#"Function("return " + x)();"#);
        // Function(...)() — outer is Function call, inner is the resulting fn call
        // We flag the Function(...) construction.
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn ignores_comment() {
        assert!(check_js("// eval(x);").is_empty());
    }

    #[test]
    fn detects_window_eval() {
        let v = check_js("window.eval(x);");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_global_this_eval() {
        let v = check_js("globalThis.eval(x);");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn ignores_non_js_file() {
        assert!(check_fail_open("eval(x);", "/docs/README.md").is_empty());
    }

    #[test]
    fn detects_multiple_eval_calls() {
        let v = check_js("eval(a);\neval(b);\neval(c);");
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn new_function_message_is_specific() {
        let v = check_js(r#"new Function("return " + x);"#);
        assert!(!v[0].fix.contains("eval()"));
        assert!(v[0].fix.contains("Function()"));
    }

    #[test]
    fn eval_message_is_specific() {
        let v = check_js("eval(x);");
        assert!(v[0].fix.contains("eval()"));
    }

    #[test]
    fn ignores_non_target_identifiers() {
        assert!(check_js("evaluate(x);").is_empty());
        assert!(check_js("callbackFunction(x);").is_empty());
        assert!(check_js("myFunction(x);").is_empty());
    }

    #[test]
    fn detects_aliased_eval_named_import() {
        let v = check_js("import { eval as e } from 'mod';\ne(userInput);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::EVAL);
        assert!(v[0].fix.contains("eval()"));
    }

    #[test]
    fn detects_aliased_function_named_import() {
        let v = check_js("import { Function as F } from 'mod';\nnew F(input);");
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("Function()"));
    }

    #[test]
    fn detects_cjs_destructured_eval_alias() {
        let v = check_js("const { eval: e } = require('mod');\ne(input);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::EVAL);
    }

    #[test]
    fn detects_namespace_member_eval() {
        let v = check_js("import * as ns from 'mod';\nns.eval(input);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::EVAL);
    }

    #[test]
    fn detects_namespace_member_function_new() {
        let v = check_js("import * as ns from 'mod';\nnew ns.Function(body);");
        assert_eq!(v.len(), 1);
        assert!(v[0].fix.contains("Function()"));
    }

    #[test]
    fn detects_cjs_namespace_member_eval() {
        let v = check_js("const ns = require('mod');\nns.eval(input);");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn local_eval_identifier_always_flagged() {
        // Regex parity: a local identifier literally named `eval` is flagged whether
        // it shadows the global, is reassigned, or aliases another function via import.
        // Naming a local `eval` is itself the smell.
        let v = check_js("import { evaluate as eval } from 'mod';\neval(x);");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_bracket_notation_eval() {
        let v = check_js(r#"window["eval"](x);"#);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_namespace_bracket_eval() {
        let v = check_js("import * as ns from 'mod';\nns[\"eval\"](x);");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn ignores_non_global_member_eval() {
        // obj.eval where obj is a local variable — not a namespace import.
        assert!(check_js("const obj = {};\nobj.eval(x);").is_empty());
    }

    #[test]
    fn fail_open_on_invalid_syntax() {
        assert!(check_fail_open("function { invalid !!!", "/src/app.ts").is_empty());
    }

    #[test]
    fn empty_file() {
        assert!(check_js("").is_empty());
    }

    #[test]
    fn css_file_not_analyzed() {
        assert!(check_fail_open("body { color: red; }", "/src/styles.css").is_empty());
    }

    #[test]
    fn nfr001_eval_under_10ms() {
        let content = concat!(
            "import { eval as e } from 'mod';\n",
            "import * as ns from 'mod';\n",
            "const { eval: cjsE } = require('mod');\n",
            "const cjsNs = require('mod');\n",
            "eval(a);\n",
            "new Function('return ' + b);\n",
            "window.eval(c);\n",
            "globalThis.eval(d);\n",
            "e(f);\n",
            "ns.eval(g);\n",
            "cjsE(h);\n",
            "cjsNs.eval(i);\n",
            "evaluate(j);\n",
            "callbackFunction(k);\n",
        );
        super::super::assert_under_10ms("eval", 100, || {
            let _ = check(content, "/src/app.ts");
        });
    }
}
