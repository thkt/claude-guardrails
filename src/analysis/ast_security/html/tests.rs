use super::super::check_js;
use crate::rules::{rule_id, Severity};

// T-019: detects_inner_html_variable_assignment
#[test]
fn detects_inner_html_variable_assignment() {
    let v = check_js("el.innerHTML = userInput;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::High);
    assert!(v[0].fix.contains("textContent"));
}

// T-019: allows_inner_html_string_literal
#[test]
fn allows_inner_html_string_literal() {
    assert!(check_js(r#"el.innerHTML = "<div>static</div>";"#).is_empty());
}

// T-019: allows_inner_html_static_template
#[test]
fn allows_inner_html_static_template() {
    assert!(check_js("el.innerHTML = `<div>static</div>`;").is_empty());
}

// T-019: detects_inner_html_template_with_expression
#[test]
fn detects_inner_html_template_with_expression() {
    let v = check_js("el.innerHTML = `<div>${userInput}</div>`;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
}

// T-019: detects_inner_html_empty_string_concat (regex 版の known limitation を解消)
#[test]
fn detects_inner_html_empty_string_concat() {
    let v = check_js(r#"el.innerHTML = "" + userInput;"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
}

// T-019: allows_inner_html_concat_of_literals
#[test]
fn allows_inner_html_concat_of_literals() {
    assert!(check_js(r#"el.innerHTML = "<div>" + "static" + "</div>";"#).is_empty());
}

// T-019 (FN-2 #377): a computed string-literal key bypassed the static-member-only
// arm (`el["innerHTML"] = userInput` slipped through).
#[test]
fn detects_inner_html_computed_string_key() {
    let v = check_js(r#"el["innerHTML"] = userInput;"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::High);
}

// T-019 (FN-2 #377): a static literal through a computed key stays safe.
#[test]
fn allows_inner_html_computed_string_key_literal() {
    assert!(check_js(r#"el["innerHTML"] = "<div>static</div>";"#).is_empty());
}

// T-019 (FN-2 #377): a dynamic (non-literal) computed key is not a known HTML sink,
// so it must not fire (`el[prop] = x` where prop is a variable).
#[test]
fn ignores_inner_html_dynamic_computed_key() {
    assert!(check_js("el[prop] = userInput;").is_empty());
}

// T-020 (FN-2 #377): outerHTML via computed string-literal key.
#[test]
fn detects_outer_html_computed_string_key() {
    let v = check_js(r#"el["outerHTML"] = userInput;"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-020: detects_outer_html_variable_assignment
#[test]
fn detects_outer_html_variable_assignment() {
    let v = check_js("el.outerHTML = userInput;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::Medium);
    assert!(v[0].fix.contains("el.replaceWith(node)"));
}

// T-020: allows_outer_html_string_literal
#[test]
fn allows_outer_html_string_literal() {
    assert!(check_js(r#"el.outerHTML = "<span>text</span>";"#).is_empty());
}

// T-021: detects_document_write_variable
#[test]
fn detects_document_write_variable() {
    let v = check_js("document.write(userInput);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::High);
    assert!(v[0].fix.contains("createElement"));
}

// T-021: detects_document_writeln_variable
#[test]
fn detects_document_writeln_variable() {
    let v = check_js("document.writeln(userInput);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::High);
}

// T-021: allows_document_write_literal
#[test]
fn allows_document_write_literal() {
    assert!(check_js(r#"document.write("<h1>hello</h1>");"#).is_empty());
}

// T-021: detects_document_write_concat_with_variable
#[test]
fn detects_document_write_concat_with_variable() {
    let v = check_js(r#"document.write("<h1>" + title + "</h1>");"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
}

// T-021: ignores_unrelated_document_method
#[test]
fn ignores_unrelated_document_method() {
    assert!(check_js("document.getElementById('x');").is_empty());
    assert!(check_js("document.createElement('div');").is_empty());
}

// T-021: ignores_non_document_write
#[test]
fn ignores_non_document_write() {
    assert!(check_js("stream.write(userInput);").is_empty());
    assert!(check_js("logger.write(userInput);").is_empty());
}

// TC-007: document.write() with zero arguments is flagged. The absence of
// a safe literal arg means `is_some_and(is_safe_html_value)` returns false,
// matching the regex-parity behavior (regex also matched `document.write()`).
#[test]
fn detects_document_write_zero_args_intent() {
    let v = check_js("document.write();");
    assert_eq!(
        v.len(),
        1,
        "zero-arg document.write() intentionally flagged"
    );
    assert_eq!(v[0].rule, rule_id::UNSAFE_HTML_INJECTION);
    assert_eq!(v[0].severity, Severity::High);
}
