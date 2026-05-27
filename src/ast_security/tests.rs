use super::*;
use std::time::Instant;

#[test]
fn fail_open_on_invalid_or_unsupported_input() {
    assert!(check_js("function { invalid syntax !!!").is_empty());
    assert!(check_js("").is_empty());
    assert!(check("body { color: red; }", "/src/styles.css").is_empty());
}

#[test]
fn bidi_rlo_in_code_blocked() {
    let v = check_js("let x = '\u{202E}' + y;");
    assert_eq!(v.len(), 1, "should detect bidi char");
    assert_eq!(v[0].severity, Severity::High);
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
}

#[test]
fn bidi_rli_in_comment_blocked() {
    let v = check_js("// comment with \u{2067} bidi\nlet x = 1;");
    assert_eq!(v.len(), 1, "should detect bidi in comments");
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
}

#[test]
fn bidi_rlm_in_string_blocked() {
    let v = check_js("const s = \"hello\u{200F}world\";");
    assert_eq!(v.len(), 1, "should detect bidi in strings");
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
}

#[test]
fn no_bidi_safe() {
    assert!(check_js("const x = 1;\nconst y = 2;").is_empty());
}

#[test]
fn multiple_bidi_reports_first() {
    let v = check_js("let a = '\u{202E}';\nlet b = '\u{202D}';");
    assert_eq!(v.len(), 1, "should report only first bidi occurrence");
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
    assert_eq!(v[0].line, Some(1), "should report first line");
}

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

#[test]
fn p1_and_p2_violations_coexist() {
    let code = concat!(
        "exec(userInput);\n",
        "const m = require(variable);\n",
        "const re = /^(a+)+$/;\n",
        "res.json({ stack: err.stack });\n",
        "fs.readFile(userInput, cb);\n",
    );
    let v = check_js(code);
    let rules: Vec<&str> = v.iter().map(|v| v.rule.as_str()).collect();
    assert!(rules.contains(&rule_id::CHILD_PROCESS_INJECTION));
    assert!(rules.contains(&rule_id::NON_LITERAL_REQUIRE));
    assert!(rules.contains(&rule_id::UNSAFE_REGEX));
    assert!(rules.contains(&rule_id::ERR_STACK_EXPOSURE));
    assert!(rules.contains(&rule_id::NON_LITERAL_FS_PATH));
    assert!(v.len() >= 5, "expected at least 5, got {}", v.len());
}

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

// T-018: nfr001_performance_under_10ms
#[test]
fn nfr001_performance_under_10ms() {
    let content = concat!(
        "const m = require('./ok');\n",
        "const n = require(variable);\n",
        "const re1 = /^(a+)+$/;\n",
        "const re2 = /^\\d+$/;\n",
        "exec('ls -la');\n",
        "exec(userInput);\n",
        "fs.readFile('./config.json', cb);\n",
        "fs.readFile(userInput, cb);\n",
        "res.json({ error: 'oops' });\n",
        "res.json({ stack: err.stack });\n",
        "const s = process.env.JWT_SECRET ?? 'fallback';\n",
        "const id = Math.random().toString(36).substring(2);\n",
        "el.innerHTML = userInput;\n",
        "el.outerHTML = `<span>${x}</span>`;\n",
        "document.write(userInput);\n",
        // TC-006: deeply-nested BinaryExpression to stress is_safe_html_value
        // recursive descent on the safe-static path (all string literals).
        "el.innerHTML = 'a' + 'b' + 'c' + 'd' + 'e' + 'f' + 'g' + 'h' + 'i' + 'j' + 'k' + 'l' + 'm' + 'n' + 'o' + 'p';\n",
        "obj[\"__proto__\"] = userInput;\n",
        "Object.assign(target, JSON.parse(input));\n",
        "_.merge(target, JSON.parse(input));\n",
        "const lookup = styleMap[variant];\n",
        "const token = Math.random();\n",
        "function generateSessionToken() { return Math.random(); }\n",
        "const fixed = Math.random().toFixed(8);\n",
    );
    let start = Instant::now();
    let iterations = 100;
    for _ in 0..iterations {
        let _ = check(content, "/src/app/api/handler/route.ts");
    }
    let elapsed = start.elapsed();
    let per_file_us = elapsed.as_micros() / iterations;
    eprintln!("NFR-001: {per_file_us}us/file ({iterations} iterations)");
    assert!(
        per_file_us < 10_000,
        "AST check exceeded 10ms/file: {per_file_us}us"
    );
}
