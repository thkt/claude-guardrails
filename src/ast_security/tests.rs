use super::*;
use std::time::Instant;

#[test]
fn err_stack_callee_variants() {
    for code in [
        "res.json({ stack: err.stack });",
        "res.status(500).json({ stack: error.stack });",
        "res.send({ stack: err.stack });",
        "response.json({ stack: err.stack });",
        "response.status(500).json({ error: err.stack });",
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 1, "failed for: {code}");
        assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE, "failed for: {code}");
    }
}

#[test]
fn non_response_callee_with_stack_safe() {
    assert!(check_js("logger.error({ stack: err.stack });").is_empty());
    assert!(check_js("console.error(err.stack);").is_empty());
}

#[test]
fn res_json_without_stack_safe() {
    assert!(check_js("res.json({ error: err.message });").is_empty());
}

#[test]
fn nested_stack_in_object() {
    let v = check_js("res.json({ data: { detail: err.stack } });");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn stack_in_conditional() {
    let v = check_js("res.json({ error: isDev ? err.stack : 'error' });");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn stack_in_logical() {
    let v = check_js("res.json({ error: err && err.stack });");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn stack_in_array() {
    let v = check_js("res.json([err.stack]);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn child_process_dynamic_arg_blocked() {
    for code in [
        "exec(userInput);",
        "execSync(cmd);",
        "spawn(variable, args);",
        "spawnSync(cmd, args);",
        "exec(`ls ${dir}`);",
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 1, "failed for: {code}");
        assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
        assert_eq!(
            v[0].rule,
            rule_id::CHILD_PROCESS_INJECTION,
            "failed for: {code}"
        );
    }
}

#[test]
fn child_process_literal_safe() {
    assert!(check_js("exec('ls -la');").is_empty());
    assert!(check_js("exec(`ls -la`);").is_empty());
    assert!(check_js("execFile('/usr/bin/git', args);").is_empty());
}

#[test]
fn fs_dynamic_path_blocked() {
    for code in [
        "fs.readFile(userInput, cb);",
        "fs.writeFileSync(variable, data);",
        "fs.readFileSync(path.join(__dirname, f));",
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 1, "failed for: {code}");
        assert_eq!(v[0].severity, Severity::Medium, "failed for: {code}");
        assert_eq!(
            v[0].rule,
            rule_id::NON_LITERAL_FS_PATH,
            "failed for: {code}"
        );
    }
}

#[test]
fn fs_static_path_safe() {
    assert!(check_js("fs.readFile('./config.json', cb);").is_empty());
    assert!(check_js("fs.readFile(__dirname + '/file', cb);").is_empty());
    assert!(check_js("fs.readFile(__filename, cb);").is_empty());
    assert!(check_js("fs.readFile(__dirname + '/sub' + '/file', cb);").is_empty());
    assert!(check_js("fs.readFile(`./config.json`, cb);").is_empty());
}

#[test]
fn fail_open_on_invalid_or_unsupported_input() {
    assert!(check_js("function { invalid syntax !!!").is_empty());
    assert!(check_js("").is_empty());
    assert!(check("body { color: red; }", "/src/styles.css").is_empty());
}

#[test]
fn member_expression_callee_variants() {
    for (code, rule) in [
        (
            r#"cp["exec"](userInput);"#,
            rule_id::CHILD_PROCESS_INJECTION,
        ),
        ("cp.exec(userInput);", rule_id::CHILD_PROCESS_INJECTION),
        ("childProcess.spawn(cmd);", rule_id::CHILD_PROCESS_INJECTION),
        (
            r#"fs["readFile"](userInput, cb);"#,
            rule_id::NON_LITERAL_FS_PATH,
        ),
        (
            r#"res["json"]({ stack: err.stack });"#,
            rule_id::ERR_STACK_EXPOSURE,
        ),
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 1, "failed for: {code}");
        assert_eq!(v[0].rule, rule, "failed for: {code}");
    }
    assert!(check_js(r#"cp["exec"]("ls -la");"#).is_empty());
    assert!(check_js("cp.exec('ls -la');").is_empty());
}

#[test]
fn fs_boundary_conditions() {
    let v = check_js("fs.readFile(__dirname + userInput, cb);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);

    let v = check_js("fs.unlink(variable, cb);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
}

#[test]
fn stack_in_template_literal() {
    let v = check_js("res.json(`error: ${err.stack}`);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn known_limitations_not_detected() {
    assert!(check_js("fileSystem.readFile(userInput, cb);").is_empty());
    assert!(check_js("require('fs').readFile(userInput, cb);").is_empty());
}

#[test]
fn stack_in_spread_contexts_blocked() {
    for code in [
        "res.json({ ...err });",
        "res.json([...err]);",
        "res.json(...args);",
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 1, "failed for: {code}");
        assert_eq!(v[0].severity, Severity::High, "failed for: {code}");
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE, "failed for: {code}");
    }
}

#[test]
fn non_spread_identifier_property_safe() {
    assert!(check_js("res.json({ data: someVar });").is_empty());
}

#[test]
fn zero_arg_calls_safe() {
    assert!(check_js("res.json();").is_empty());
    assert!(check_js("exec();").is_empty());
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
fn non_literal_require_variable_blocked() {
    let v = check_js("const m = require(variable);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].severity, Severity::Medium);
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
}

#[test]
fn require_string_literal_safe() {
    assert!(check_js("const m = require('./module');").is_empty());
}

#[test]
fn require_static_template_safe() {
    assert!(check_js("const m = require(`./module`);").is_empty());
}

#[test]
fn require_dynamic_template_blocked() {
    let v = check_js("const m = require(`./modules/${name}`);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
}

#[test]
fn require_no_args_safe() {
    assert!(check_js("require();").is_empty());
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

#[test]
fn err_stack_skipped_in_ui_component() {
    let v = check(
        "res.json({ stack: err.stack });",
        "/src/components/ErrorView.tsx",
    );
    assert!(v.is_empty(), "UI component must skip err-stack: {v:?}");
}

#[test]
fn err_stack_skipped_in_util_file() {
    let v = check("res.json({ stack: err.stack });", "/src/utils/format.ts");
    assert!(v.is_empty(), "util must skip err-stack: {v:?}");
}

#[test]
fn err_stack_detected_in_pages_api() {
    let v = check("res.json({ stack: err.stack });", "/src/pages/api/users.ts");
    assert_eq!(v.len(), 1, "pages/api must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn err_stack_detected_in_app_route() {
    let v = check(
        "export async function GET() { res.json({ stack: err.stack }); }",
        "/src/app/orders/[id]/route.ts",
    );
    assert_eq!(v.len(), 1, "app/**/route.ts must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}

#[test]
fn err_stack_skipped_when_only_use_server_no_api_path() {
    let v = check(
        "'use server';\nres.json({ stack: err.stack });",
        "/src/lib/helpers.ts",
    );
    assert!(v.is_empty(), "err-stack requires api/route path: {v:?}");
}

#[test]
fn fs_path_skipped_in_ui_component() {
    let v = check("fs.readFile(userInput, cb);", "/src/components/View.tsx");
    assert!(v.is_empty(), "UI component must skip fs-path: {v:?}");
}

#[test]
fn fs_path_skipped_in_util_file() {
    let v = check("fs.readFile(userInput, cb);", "/src/utils/loader.ts");
    assert!(v.is_empty(), "util must skip fs-path: {v:?}");
}

#[test]
fn fs_path_detected_with_use_server_directive() {
    let v = check(
        "'use server';\nfs.readFile(userInput, cb);",
        "/src/lib/actions.ts",
    );
    assert_eq!(v.len(), 1, "use server must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
}

#[test]
fn require_skipped_in_ui_component() {
    let v = check("require(variable);", "/src/components/View.tsx");
    assert!(v.is_empty(), "UI component must skip require: {v:?}");
}

#[test]
fn require_detected_with_use_server_directive() {
    let v = check("'use server';\nrequire(variable);", "/src/lib/actions.ts");
    assert_eq!(v.len(), 1, "use server must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
}

#[test]
fn child_process_skipped_in_ui_component() {
    let v = check("exec(userInput);", "/src/components/View.tsx");
    assert!(v.is_empty(), "UI component must skip exec: {v:?}");
}

#[test]
fn child_process_detected_with_use_server_directive() {
    let v = check("'use server';\nexec(userInput);", "/src/lib/actions.ts");
    assert_eq!(v.len(), 1, "use server must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
}

#[test]
fn detects_inline_use_server_inside_function_body() {
    let code = r"
        export async function submitForm(formData) {
            'use server';
            fs.readFile(formData.get('path'), cb);
        }
    ";
    let v = check(code, "/src/app/page.tsx");
    assert_eq!(v.len(), 1, "inline use server must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
}

#[test]
fn inline_use_server_scope_exits_with_function() {
    let code = r"
        async function action() {
            'use server';
            require(modulePath);
        }
        fs.readFile(unsafePath, cb);
    ";
    let v = check(code, "/src/components/Form.tsx");
    assert_eq!(v.len(), 1, "only inner call flags: {v:?}");
    assert_eq!(v[0].rule, rule_id::NON_LITERAL_REQUIRE);
}

#[test]
fn err_stack_detected_in_root_app_route() {
    let v = check(
        "export async function GET() { res.json({ stack: err.stack }); }",
        "/src/app/route.ts",
    );
    assert_eq!(v.len(), 1, "root app/route.ts must flag: {v:?}");
    assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
}
