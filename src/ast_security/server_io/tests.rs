use super::super::{check, check_js};
use crate::rules::{rule_id, Severity};

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
