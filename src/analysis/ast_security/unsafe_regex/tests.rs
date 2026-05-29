use super::super::check_js;
use crate::rules::{rule_id, Severity};

#[test]
fn unsafe_regex_nested_quantifier_blocked() {
    let v = check_js("const re = /^(a+)+$/;");
    assert_eq!(v.len(), 1, "should detect nested quantifier");
    assert_eq!(v[0].severity, Severity::Medium);
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}

#[test]
fn unsafe_regex_digit_nested_blocked() {
    let v = check_js("const re = /^(\\d+)+$/;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}

#[test]
fn unsafe_regex_alternation_with_quantifier_blocked() {
    let v = check_js("const re = /^(a+|b+)*$/;");
    assert_eq!(v.len(), 1, "should detect quantifier in quantified group");
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}

#[test]
fn unsafe_regex_brace_quantifier_blocked() {
    // {n,} inside quantified group
    let v = check_js("const re = /^(\\d{2,}){3,}$/;");
    assert_eq!(
        v.len(),
        1,
        "should detect brace quantifier as inner quantifier"
    );
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}

#[test]
fn unsafe_regex_optional_in_quantified_group_blocked() {
    // (a?)+ — ? is a quantifier, star height 2
    let v = check_js("const re = /^(a?)+$/;");
    assert_eq!(v.len(), 1, "should detect ? as inner quantifier");
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}

#[test]
fn safe_regex_quantified_group_with_optional_outer() {
    // (a+)? — outer ? is bounded (0-1), but inner + is unbounded
    // This IS flagged because inner has +, outer has ?
    let v = check_js("const re = /^(a+)?$/;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}

#[test]
fn safe_regex_simple_quantifier() {
    assert!(check_js("const re = /^\\d+$/;").is_empty());
}

#[test]
fn safe_regex_char_class_quantifier() {
    assert!(check_js("const re = /^[a-z]+$/;").is_empty());
}

#[test]
fn safe_regex_quantifier_inside_char_class() {
    // + inside [...] is literal, not a quantifier
    assert!(check_js("const re = /^([a+])+$/;").is_empty());
}

#[test]
fn safe_regex_escaped_quantifier() {
    let v = check_js("const re = /^(a\\+)+$/;");
    assert!(
        v.is_empty(),
        "escaped + should not be treated as quantifier"
    );
}

#[test]
fn dynamic_regexp_not_analyzed() {
    assert!(check_js("const re = new RegExp(pattern);").is_empty());
}

#[test]
fn safe_regex_non_capturing_group() {
    assert!(check_js("const re = /^(?:foo)+$/;").is_empty());
    assert!(check_js("const re = /^(?:a|b)+$/;").is_empty());
    assert!(check_js("const re = /^(?:ab)*$/;").is_empty());
}

#[test]
fn safe_regex_lookaround_groups() {
    assert!(check_js("const re = /^(?=foo).+$/;").is_empty());
    assert!(check_js("const re = /^(?!foo).+$/;").is_empty());
    assert!(check_js("const re = /^(?<=foo).+$/;").is_empty());
    assert!(check_js("const re = /^(?<!foo).+$/;").is_empty());
}

#[test]
fn unsafe_regex_nested_inside_non_capturing_group() {
    // (?:a+)+ — inner a+ is a real quantifier, outer + on group = nested
    let v = check_js("const re = /^(?:a+)+$/;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_REGEX);
}
