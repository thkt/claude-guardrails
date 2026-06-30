use super::SecurityVisitor;
use crate::analysis::ast;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::{AssignmentExpression, AssignmentTarget, CallExpression, Expression};

/// (object identifier alternatives, method name alternatives, fix message).
/// Each row registers an assignment-style merge sink that pollutes its target
/// when the source is untrusted (see `is_untrusted_source`).
const POLLUTION_MERGE_SINKS: &[(&[&str], &[&str], &str)] = &[
    (
        &["Object"],
        &["assign"],
        "Object.assign with an untrusted source can pollute prototype. Use Object.create(null) target (a plain {} still inherits __proto__).",
    ),
    (
        &["_", "lodash"],
        &["merge", "defaultsDeep"],
        "lodash merge/defaultsDeep with an untrusted source can pollute prototype. Use Object.create(null) target.",
    ),
];

impl SecurityVisitor<'_> {
    pub(super) fn check_prototype_pollution(&mut self, expr: &AssignmentExpression) {
        if self.is_test_file {
            return;
        }
        if assignment_target_has_pollution_segment(&expr.left) {
            self.push_violation(
                rule_id::PROTOTYPE_POLLUTION,
                Severity::High,
                "Assignment via __proto__/constructor/prototype enables prototype pollution. Use Object.defineProperty or a Map.",
                expr.span,
            );
        }
    }

    fn check_assign_with_untrusted_source(&mut self, call: &CallExpression, fix: &str) {
        let Some(target) = call.arguments.first().and_then(|a| a.as_expression()) else {
            return;
        };
        if is_null_prototype_target(target) {
            return;
        }
        let has_untrusted = call
            .arguments
            .iter()
            .skip(1)
            .any(|arg| arg.as_expression().is_some_and(is_untrusted_source));
        if has_untrusted {
            self.push_violation(rule_id::PROTOTYPE_POLLUTION, Severity::High, fix, call.span);
        }
    }

    pub(super) fn check_merge_pollution_sinks(&mut self, call: &CallExpression) {
        if self.is_test_file {
            return;
        }
        let Some((obj, method)) = ast::member_name(&call.callee) else {
            return;
        };
        let Some(&(_, _, fix)) = POLLUTION_MERGE_SINKS.iter().find(|(objs, methods, _)| {
            objs.iter().any(|o| ast::is_ident(obj, o)) && methods.contains(&method)
        }) else {
            return;
        };
        self.check_assign_with_untrusted_source(call, fix);
    }
}

/// Returns true only for `Object.create(null)`. A plain `{}` is intentionally
/// rejected because it inherits `Object.prototype` and the `__proto__` setter
/// fires when the merge source carries that key.
fn is_null_prototype_target(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    let Some((obj, "create")) = ast::member_name(&call.callee) else {
        return false;
    };
    if !ast::is_ident(obj, "Object") {
        return false;
    }
    matches!(
        call.arguments.first().and_then(|a| a.as_expression()),
        Some(Expression::NullLiteral(_))
    )
}

fn is_pollution_key(s: &str) -> bool {
    matches!(s, "__proto__" | "constructor" | "prototype")
}

fn assignment_target_has_pollution_segment(target: &AssignmentTarget) -> bool {
    match target {
        AssignmentTarget::StaticMemberExpression(sme) => {
            is_pollution_key(sme.property.name.as_str()) || object_chain_is_pollution(&sme.object)
        }
        AssignmentTarget::ComputedMemberExpression(cme) => {
            computed_key_is_pollution(&cme.expression) || object_chain_is_pollution(&cme.object)
        }
        _ => false,
    }
}

#[derive(Default)]
struct ChainSegments {
    proto: bool,
    constructor: bool,
    prototype: bool,
}

fn mark_segment(name: &str, seg: &mut ChainSegments) {
    match name {
        "__proto__" => seg.proto = true,
        "constructor" => seg.constructor = true,
        "prototype" => seg.prototype = true,
        _ => {}
    }
}

fn collect_chain_segments(expr: &Expression, seg: &mut ChainSegments) {
    match expr {
        Expression::StaticMemberExpression(sme) => {
            mark_segment(sme.property.name.as_str(), seg);
            collect_chain_segments(&sme.object, seg);
        }
        Expression::ComputedMemberExpression(cme) => {
            if let Some(key) = ast::static_key(&cme.expression) {
                mark_segment(key, seg);
            }
            collect_chain_segments(&cme.object, seg);
        }
        _ => {}
    }
}

/// True when the assignment's object chain (everything left of the final write
/// key) is exploit-shaped. `__proto__` anywhere reaches the live prototype, so
/// it always fires. A lone `prototype` or lone `constructor` segment is benign:
/// `X.prototype.method = ...` and polyfills (`Array.prototype.flat = ...`)
/// define methods, not pollute. The classic gadget needs `constructor` AND
/// `prototype` together (`obj.constructor.prototype.x = ...`), so require both.
fn object_chain_is_pollution(expr: &Expression) -> bool {
    let mut seg = ChainSegments::default();
    collect_chain_segments(expr, &mut seg);
    seg.proto || (seg.constructor && seg.prototype)
}

fn computed_key_is_pollution(expr: &Expression) -> bool {
    ast::static_key(expr).is_some_and(is_pollution_key)
}

fn is_json_parse_call(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    matches!(ast::member_name(&call.callee), Some((obj, "parse")) if ast::is_ident(obj, "JSON"))
}

/// An untrusted merge source: a `JSON.parse(...)` result, or a canonical Express
/// request input (`req.body`/`query`/`params`, `request.*`). The bare-identifier
/// allowance (T-031/T-036) stands — only these statically recognizable shapes are
/// treated as untrusted (FN-3 #377).
fn is_untrusted_source(expr: &Expression) -> bool {
    is_json_parse_call(expr) || is_request_input(expr)
}

fn is_request_input(expr: &Expression) -> bool {
    let Some((object, property)) = ast::member_name(expr) else {
        return false;
    };
    matches!(property, "body" | "query" | "params")
        && (ast::is_ident(object, "req") || ast::is_ident(object, "request"))
}

#[cfg(test)]
mod tests {
    use super::super::{check, check_js};
    use crate::rules::{rule_id, Severity};

    // T-022: prototype_pollution_literal_proto_assignment_blocked
    #[test]
    fn prototype_pollution_literal_proto_assignment_blocked() {
        let v = check_js(r#"obj["__proto__"] = x;"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-023: prototype_pollution_static_proto_assignment_blocked
    #[test]
    fn prototype_pollution_static_proto_assignment_blocked() {
        let v = check_js("obj.__proto__ = x;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-383-3 (#383): substitution-free template-literal pollution keys resolve
    // like string-literal keys — both the final write key and a chain segment.
    #[test]
    fn prototype_pollution_template_key_blocked() {
        for code in [
            "target[`__proto__`] = v;",
            "o[`constructor`][`prototype`].admin = true;",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
        }
    }

    // T-383-3 (#383): a benign template-literal key does not fire.
    #[test]
    fn prototype_pollution_benign_template_key_allowed() {
        assert!(check_js("o[`bar`] = v;").is_empty());
    }

    // T-024: prototype_pollution_constructor_prototype_assignment_blocked
    #[test]
    fn prototype_pollution_constructor_prototype_assignment_blocked() {
        for code in [
            r#"obj["constructor"] = x;"#,
            "obj.constructor = x;",
            r#"obj["prototype"] = x;"#,
            "obj.prototype = x;",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
        }
    }

    // T-025: prototype_pollution_variable_key_allowed (Record lookup FP suppression)
    #[test]
    fn prototype_pollution_variable_key_allowed() {
        assert!(check_js("obj[key] = x;").is_empty());
        assert!(check_js("obj[someVar] = x;").is_empty());
        assert!(check_js("styleMap[variant] = value;").is_empty());
    }

    // T-026: prototype_pollution_normal_property_allowed
    #[test]
    fn prototype_pollution_normal_property_allowed() {
        assert!(check_js("obj.knownProp = x;").is_empty());
        assert!(check_js(r#"obj["safeName"] = x;"#).is_empty());
    }

    // T-027: prototype_pollution_pollution_key_read_allowed
    #[test]
    fn prototype_pollution_pollution_key_read_allowed() {
        assert!(check_js("if (instance.constructor === Foo) {}").is_empty());
        assert!(check_js("const c = obj.constructor;").is_empty());
        assert!(check_js("const p = obj.__proto__;").is_empty());
    }

    // T-028: prototype_pollution_object_assign_json_parse_blocked
    #[test]
    fn prototype_pollution_object_assign_json_parse_blocked() {
        let v = check_js("Object.assign(target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-029: prototype_pollution_object_assign_empty_literal_target_blocked
    // `{}` still inherits Object.prototype, so the parsed payload's `__proto__`
    // setter fires. Object.create(null) is the only safe target.
    #[test]
    fn prototype_pollution_object_assign_empty_literal_target_blocked() {
        let v = check_js("Object.assign({}, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-030: prototype_pollution_object_assign_null_proto_target_allowed
    #[test]
    fn prototype_pollution_object_assign_null_proto_target_allowed() {
        assert!(check_js("Object.assign(Object.create(null), JSON.parse(input));").is_empty());
    }

    // T-031: prototype_pollution_object_assign_static_source_allowed
    #[test]
    fn prototype_pollution_object_assign_static_source_allowed() {
        assert!(check_js("Object.assign(target, { a: 1, b: 2 });").is_empty());
        assert!(check_js("Object.assign(target, source);").is_empty());
    }

    // T-032: prototype_pollution_object_assign_multi_source_blocked
    #[test]
    fn prototype_pollution_object_assign_multi_source_blocked() {
        let v = check_js("Object.assign(target, { static: 1 }, JSON.parse(x));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-033: prototype_pollution_lodash_merge_json_parse_blocked
    #[test]
    fn prototype_pollution_lodash_merge_json_parse_blocked() {
        let v = check_js("_.merge(target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-034: prototype_pollution_lodash_defaults_deep_blocked
    #[test]
    fn prototype_pollution_lodash_defaults_deep_blocked() {
        let v = check_js("_.defaultsDeep(target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-035: prototype_pollution_lodash_full_name_blocked
    #[test]
    fn prototype_pollution_lodash_full_name_blocked() {
        for code in [
            "lodash.merge(target, JSON.parse(input));",
            "lodash.defaultsDeep(target, JSON.parse(input));",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
        }
    }

    // T-036: prototype_pollution_lodash_static_source_allowed
    #[test]
    fn prototype_pollution_lodash_static_source_allowed() {
        assert!(check_js("_.merge(target, { a: 1 });").is_empty());
        assert!(check_js("_.merge(target, source);").is_empty());
    }

    // T-037: prototype_pollution_lodash_safe_target_allowed
    #[test]
    fn prototype_pollution_lodash_safe_target_allowed() {
        assert!(check_js("_.merge(Object.create(null), JSON.parse(input));").is_empty());
    }

    // T-037b: prototype_pollution_lodash_empty_literal_target_blocked
    #[test]
    fn prototype_pollution_lodash_empty_literal_target_blocked() {
        let v = check_js("_.merge({}, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-038: prototype_pollution_record_lookup_patterns_allowed
    #[test]
    fn prototype_pollution_record_lookup_patterns_allowed() {
        for code in [
            "const label = translations[locale];",
            "const color = STATUS_LABELS[order.status];",
            "const style = styleMap[variant];",
            "const item = items[0];",
            "const v = arr[idx + 1];",
            "obj[key] += 1;",
        ] {
            assert!(check_js(code).is_empty(), "false positive for: {code}");
        }
    }

    // T-046 (FN-3 #377): a canonical request-input source (`req.body`/`query`/
    // `params`, `request.*`) is untrusted just like `JSON.parse(...)`. These
    // slipped through when only `JSON.parse` counted as untrusted.
    #[test]
    fn prototype_pollution_object_assign_request_input_blocked() {
        for code in [
            "Object.assign(target, req.body);",
            "Object.assign(target, req.query);",
            "Object.assign(target, req.params);",
            "Object.assign(target, request.body);",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
            assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
        }
    }

    // T-047 (FN-3 #377): lodash merge sinks fed a request-input source.
    #[test]
    fn prototype_pollution_lodash_merge_request_input_blocked() {
        for code in [
            "_.merge(target, req.body);",
            "lodash.defaultsDeep(target, request.query);",
        ] {
            let v = check_js(code);
            assert_eq!(v.len(), 1, "failed for: {code}");
            assert_eq!(
                v[0].rule,
                rule_id::PROTOTYPE_POLLUTION,
                "failed for: {code}"
            );
        }
    }

    // T-048 (FN-3 #377): an unrelated object's same-named property is not a
    // request-input source, so the bare-identifier allowance (T-031/T-036) holds
    // for it (`config.body` is not `req.body`).
    #[test]
    fn prototype_pollution_non_request_member_source_allowed() {
        assert!(check_js("Object.assign(target, config.body);").is_empty());
        assert!(check_js("_.merge(target, settings.params);").is_empty());
    }

    // T-039: prototype_pollution_no_call_no_assignment_allowed
    #[test]
    fn prototype_pollution_no_call_no_assignment_allowed() {
        assert!(check_js("const p = Object.assign(target, source);").is_empty());
        assert!(check_js("const merged = _.merge({}, defaults);").is_empty());
    }

    // T-040: prototype_pollution_chain_proto_polluted_blocked
    #[test]
    fn prototype_pollution_chain_proto_polluted_blocked() {
        let v = check_js("obj.__proto__.polluted = value;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-041: prototype_pollution_chain_constructor_prototype_blocked
    #[test]
    fn prototype_pollution_chain_constructor_prototype_blocked() {
        let v = check_js("obj.constructor.prototype.admin = true;");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-042: prototype_pollution_chain_computed_key_blocked
    #[test]
    fn prototype_pollution_chain_computed_key_blocked() {
        let v = check_js(r#"obj["__proto__"]["polluted"] = x;"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-043: prototype_pollution_test_file_skipped
    // Test files commonly stub prototypes (e.g. `Function.prototype.bind = jest.fn()`).
    #[test]
    fn prototype_pollution_test_file_skipped() {
        for path in [
            "/src/util.test.ts",
            "/src/util.spec.tsx",
            "/src/util.test.js",
        ] {
            let v = check("Function.prototype.bind = jest.fn();", path);
            assert!(v.is_empty(), "expected 0 violations for {path}");
        }
    }

    // T-044: prototype_pollution_bracket_form_blocked
    // ast::member_name unwrap also accepts `Object["assign"]` / `JSON["parse"]` form,
    // closing a trivial bracket-string bypass.
    #[test]
    fn prototype_pollution_bracket_form_blocked() {
        let v = check_js(r#"Object["assign"](target, JSON["parse"](input));"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-383-5 (#383): the merge-sink callee resolves through member_name, so a
    // substitution-free template-literal method key fires like the bracket-string
    // form (T-044). Guards the member_name -> static_key wiring at this consumer.
    #[test]
    fn prototype_pollution_template_callee_blocked() {
        let v = check_js("Object[`assign`](target, JSON.parse(input));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::PROTOTYPE_POLLUTION);
    }

    // T-045: prototype_pollution_method_definition_allowed
    // A write whose final key is an ordinary method name does not pollute even
    // when `prototype` sits mid-chain: `X.prototype.method = ...` is the standard
    // way to define methods and polyfills (`Array.prototype.flat = ...`). Only a
    // pollution key as the final write target, a `__proto__` segment, or a
    // `constructor`+`prototype` gadget is exploit-shaped.
    #[test]
    fn prototype_pollution_method_definition_allowed() {
        for code in [
            "MyClass.prototype.render = function () {};",
            "Array.prototype.flat = function () {};",
            "Foo.prototype.bar = () => {};",
        ] {
            assert!(check_js(code).is_empty(), "false positive for: {code}");
        }
    }
}
