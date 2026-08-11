//! `rule_id` 単位のスモークテスト (Issue #98 受け入れ条件 #2)。
//! 各ルールについて違反 1 件 + 健全 1 件のペアを `--json` envelope の
//! `data.violations[].rule` で assert する。健全側は `file_pattern` が match
//! する正常コードを使い、「ルールが skip されただけ」を検出から除外する。

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run_guardrails_json(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guardrails");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn hook_input(file_path: &str, content: &str) -> String {
    serde_json::json!({
        "tool_name": "Write",
        "tool_input": { "file_path": file_path, "content": content }
    })
    .to_string()
}

fn parse_envelope(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!("expected JSON envelope, got: {stdout}\nerror: {e}")
    })
}

fn violations_for_rule<'a>(envelope: &'a Value, rule_id: &str) -> Vec<&'a Value> {
    envelope["data"]["violations"]
        .as_array()
        .unwrap_or_else(|| panic!("data.violations missing: {envelope}"))
        .iter()
        .filter(|v| v["rule"] == rule_id)
        .collect()
}

fn assert_rule_fires(rule_id: &str, file_path: &str, content: &str) {
    let output = run_guardrails_json(hook_input(file_path, content).as_bytes());
    let envelope = parse_envelope(&output);
    let hits = violations_for_rule(&envelope, rule_id);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let oxlint_hint = if rule_id.starts_with("oxlint/") {
        "Note: this rule requires the oxlint binary. Run \
         `cargo run -- --json prefetch` to populate the cache before testing.\n"
    } else {
        ""
    };
    assert!(
        !hits.is_empty(),
        "expected at least one {rule_id} violation in {envelope}\n{oxlint_hint}stderr: {stderr}"
    );
}

fn assert_rule_silent(rule_id: &str, file_path: &str, content: &str) {
    let output = run_guardrails_json(hook_input(file_path, content).as_bytes());
    let envelope = parse_envelope(&output);
    let hits = violations_for_rule(&envelope, rule_id);
    assert!(
        hits.is_empty(),
        "expected no {rule_id} violations, got: {hits:?}\nfull envelope: {envelope}"
    );
}

// T-001: eval (line-regex rule, RE_JS_FILE scope)
#[test]
fn eval_fires_on_direct_eval() {
    assert_rule_fires("eval", "/src/app.ts", "eval(userInput);");
}

// T-002: eval silent when file_pattern matches but content has no eval
#[test]
fn eval_silent_on_plain_code() {
    assert_rule_silent("eval", "/src/app.ts", "export function main() {}\n");
}

// T-003: unsafe-html-injection (AST rule via ast_security)
#[test]
fn unsafe_html_injection_fires_on_nonliteral_inner_html() {
    assert_rule_fires(
        "unsafe-html-injection",
        "/src/page.ts",
        "el.innerHTML = userInput;",
    );
}

// T-004: unsafe-html-injection silent on literal HTML string
#[test]
fn unsafe_html_injection_silent_on_literal_inner_html() {
    assert_rule_silent(
        "unsafe-html-injection",
        "/src/page.ts",
        "el.innerHTML = '<p>safe</p>';",
    );
}

// T-005: non-literal-fs-path (AST rule + app/api/ file_pattern scope)
#[test]
fn non_literal_fs_path_fires_in_app_api() {
    assert_rule_fires(
        "non-literal-fs-path",
        "/app/api/route.ts",
        "import fs from 'fs';\nfs.readFile(userInput, callback);\n",
    );
}

// T-006: non-literal-fs-path silent on literal arg in app/api/ scope
#[test]
fn non_literal_fs_path_silent_on_literal_in_app_api() {
    assert_rule_silent(
        "non-literal-fs-path",
        "/app/api/route.ts",
        "import fs from 'fs';\nfs.readFile('/etc/config.json', callback);\n",
    );
}

// T-007: sensitive-file (file_path-only, Critical)
#[test]
fn sensitive_file_fires_on_dotenv_path() {
    assert_rule_fires("sensitive-file", "/project/.env", "DB_URL=...");
}

// T-008: sensitive-file silent on normal source path
#[test]
fn sensitive_file_silent_on_normal_path() {
    assert_rule_silent("sensitive-file", "/src/app.ts", "export const x = 1;");
}

// T-009: generated-file (file_path-only)
#[test]
fn generated_file_fires_on_generated_suffix() {
    assert_rule_fires(
        "generated-file",
        "/src/api/client.generated.ts",
        "export const X = 1;",
    );
}

// T-010: generated-file silent on regular component path
#[test]
fn generated_file_silent_on_regular_component() {
    assert_rule_silent(
        "generated-file",
        "/src/components/Button.tsx",
        "export const Button = () => null;",
    );
}

// T-011: crypto-weak (line-regex, MD5/SHA1/DES/RC4)
#[test]
fn crypto_weak_fires_on_md5() {
    assert_rule_fires(
        "crypto-weak",
        "/src/hash.ts",
        "const h = createHash('md5');",
    );
}

// T-012: crypto-weak silent on strong algorithm
#[test]
fn crypto_weak_silent_on_sha256() {
    assert_rule_silent(
        "crypto-weak",
        "/src/hash.ts",
        "const h = createHash('sha256');",
    );
}

// T-013: dom-access (.tsx/.jsx scope, document.* APIs)
#[test]
fn dom_access_fires_on_get_element_by_id_in_tsx() {
    assert_rule_fires(
        "dom-access",
        "/src/components/App.tsx",
        "const el = document.getElementById('root');",
    );
}

// T-014: dom-access silent on plain React code
#[test]
fn dom_access_silent_on_useref() {
    assert_rule_silent(
        "dom-access",
        "/src/components/App.tsx",
        "const ref = useRef(null);",
    );
}

// T-015: http-resource (regex http:// excluding localhost)
#[test]
fn http_resource_fires_on_http_external() {
    assert_rule_fires(
        "http-resource",
        "/src/api.ts",
        r#"fetch("http://api.example.com/data");"#,
    );
}

// T-016: http-resource silent on https external
#[test]
fn http_resource_silent_on_https() {
    assert_rule_silent(
        "http-resource",
        "/src/api.ts",
        r#"fetch("https://api.example.com/data");"#,
    );
}

// T-017: security (line-regex, setTimeout/postMessage etc.)
#[test]
fn security_fires_on_settimeout_string() {
    assert_rule_fires("security", "/src/app.ts", "setTimeout('foo()', 100);");
}

// T-018: security silent on function-reference setTimeout
#[test]
fn security_silent_on_settimeout_function() {
    assert_rule_silent("security", "/src/app.ts", "setTimeout(() => doX(), 100);");
}

// T-019: dangerous-inner-html (.tsx/.jsx, JSX attribute)
#[test]
fn dangerous_inner_html_fires_on_jsx_attribute() {
    assert_rule_fires(
        "dangerous-inner-html",
        "/src/components/Post.tsx",
        "export const Post = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />;",
    );
}

// T-020: dangerous-inner-html silent on safe JSX
#[test]
fn dangerous_inner_html_silent_on_plain_jsx() {
    assert_rule_silent(
        "dangerous-inner-html",
        "/src/components/Post.tsx",
        "export const Post = () => <div>safe content</div>;",
    );
}

// T-021: transaction-boundary (multiple writes without tx wrapper, scoped dir)
#[test]
fn transaction_boundary_fires_on_multiple_writes_in_usecase() {
    assert_rule_fires(
        "transaction-boundary",
        "/src/usecases/handler.ts",
        "async function handle() {\n  await user.save();\n  await order.create();\n}",
    );
}

// T-022: transaction-boundary silent when wrapped in transaction
#[test]
fn transaction_boundary_silent_when_wrapped() {
    assert_rule_silent(
        "transaction-boundary",
        "/src/usecases/handler.ts",
        "async function handle() {\n  await db.transaction(async () => {\n    await user.save();\n    await order.create();\n  });\n}",
    );
}

// T-023: test-location (src/ + .test/spec/__tests__)
#[test]
fn test_location_fires_on_test_file_in_src() {
    assert_rule_fires(
        "test-location",
        "/project/src/utils/helper.test.ts",
        "import { helper } from './helper';\nit('works', () => {});",
    );
}

// T-024: test-location silent on test file outside src/
#[test]
fn test_location_silent_on_test_outside_src() {
    assert_rule_silent(
        "test-location",
        "/project/tests/utils/helper.test.ts",
        "import { helper } from '../../src/utils/helper';\nit('works', () => {});",
    );
}

// T-025: test-assertion (test body without expect/assert)
#[test]
fn test_assertion_fires_on_test_without_expect() {
    assert_rule_fires(
        "test-assertion",
        "/src/utils.test.ts",
        "it('should do something', () => {\n  const result = doSomething();\n});",
    );
}

// T-026: test-assertion silent when expect() is present
#[test]
fn test_assertion_silent_on_test_with_expect() {
    assert_rule_silent(
        "test-assertion",
        "/src/utils.test.ts",
        "it('should do something', () => {\n  expect(doSomething()).toBe(1);\n});",
    );
}

// T-027: sync-io (readFileSync etc., excludes config/scripts)
#[test]
fn sync_io_fires_on_read_file_sync() {
    assert_rule_fires(
        "sync-io",
        "/src/loader.ts",
        "import fs from 'fs';\nconst data = fs.readFileSync('config.json');",
    );
}

// T-028: sync-io silent on async fs API
#[test]
fn sync_io_silent_on_async_read_file() {
    assert_rule_silent(
        "sync-io",
        "/src/loader.ts",
        "import { readFile } from 'fs/promises';\nconst data = await readFile('config.json');",
    );
}

// T-029: bundle-size (full lodash/moment imports)
#[test]
fn bundle_size_fires_on_lodash_full_import() {
    assert_rule_fires(
        "bundle-size",
        "/src/util.ts",
        "import _ from 'lodash';\nconst x = _.map([], (i) => i);",
    );
}

// T-030: bundle-size silent on tree-shakable import
#[test]
fn bundle_size_silent_on_lodash_es() {
    assert_rule_silent(
        "bundle-size",
        "/src/util.ts",
        "import { map } from 'lodash-es';\nconst x = map([], (i) => i);",
    );
}

// T-031: flaky-test (setTimeout / Math.random in test files)
#[test]
fn flaky_test_fires_on_settimeout_in_test() {
    assert_rule_fires(
        "flaky-test",
        "/src/utils.test.ts",
        "it('waits', () => {\n  setTimeout(() => done(), 100);\n});",
    );
}

// T-032: flaky-test silent on fake timer usage
#[test]
fn flaky_test_silent_on_fake_timers() {
    assert_rule_silent(
        "flaky-test",
        "/src/utils.test.ts",
        "it('waits', () => {\n  jest.useFakeTimers();\n  expect(1).toBe(1);\n});",
    );
}

// T-033: sensitive-logging (console.log + password/token/secret keyword)
#[test]
fn sensitive_logging_fires_on_password_log() {
    assert_rule_fires(
        "sensitive-logging",
        "/src/auth.ts",
        "console.log('user password:', password);",
    );
}

// T-034: sensitive-logging silent on benign log
#[test]
fn sensitive_logging_silent_on_benign_log() {
    assert_rule_silent(
        "sensitive-logging",
        "/src/auth.ts",
        "console.log('user:', userName);",
    );
}

// T-035: hardcoded-secret (Bearer/Basic token literal).
// Build the fixture at runtime so the Rust source itself does not contain
// a literal "Bearer <token>" pattern that would trip hardcoded-secret on
// this file (file_pattern = RE_ALL_FILES) at the next guardrails scan.
#[test]
fn hardcoded_secret_fires_on_bearer_token_literal() {
    let content = format!(
        r#"const auth = "{} {}";"#,
        "Bearer", "abc123def456ghi789jkl012"
    );
    assert_rule_fires("hardcoded-secret", "/src/api.ts", &content);
}

// T-036: hardcoded-secret silent on plain string literal
#[test]
fn hardcoded_secret_silent_on_plain_string() {
    assert_rule_silent(
        "hardcoded-secret",
        "/src/api.ts",
        r#"const msg = "Hello world";"#,
    );
}

// T-037: raw-html (string concat with tag literal + variable)
#[test]
fn raw_html_fires_on_string_concat() {
    assert_rule_fires(
        "raw-html",
        "/src/render.ts",
        r"const out = '<div>' + userName + '</div>';",
    );
}

// T-038: raw-html silent on literal-only HTML string
#[test]
fn raw_html_silent_on_literal_only() {
    assert_rule_silent(
        "raw-html",
        "/src/render.ts",
        r"const out = '<div>static</div>';",
    );
}

// T-039: open-redirect (location.href = nonliteral)
#[test]
fn open_redirect_fires_on_location_href_user_input() {
    assert_rule_fires(
        "open-redirect",
        "/src/router.ts",
        "function go(url) {\n  location.href = url;\n}",
    );
}

// T-040: open-redirect silent on literal URL
#[test]
fn open_redirect_silent_on_literal_url() {
    assert_rule_silent(
        "open-redirect",
        "/src/router.ts",
        "function go() {\n  location.href = '/home';\n}",
    );
}

// T-041: err-stack-exposure (res.json with err.stack in app/api/)
#[test]
fn err_stack_exposure_fires_in_api_route() {
    assert_rule_fires(
        "err-stack-exposure",
        "/app/api/route.ts",
        "export function GET(req, res) {\n  try { doX(); } catch (err) {\n    res.json({ error: err.stack });\n  }\n}",
    );
}

// T-042: err-stack-exposure silent on generic error message
#[test]
fn err_stack_exposure_silent_on_generic_message() {
    assert_rule_silent(
        "err-stack-exposure",
        "/app/api/route.ts",
        "export function GET(req, res) {\n  try { doX(); } catch (err) {\n    res.json({ error: 'Internal error' });\n  }\n}",
    );
}

// T-043: child-process-injection (exec(nonliteral) in api scope)
#[test]
fn child_process_injection_fires_on_nonliteral_exec() {
    assert_rule_fires(
        "child-process-injection",
        "/app/api/route.ts",
        "import { exec } from 'child_process';\nexec(userInput);",
    );
}

// T-044: child-process-injection silent on literal command
#[test]
fn child_process_injection_silent_on_literal_command() {
    assert_rule_silent(
        "child-process-injection",
        "/app/api/route.ts",
        "import { exec } from 'child_process';\nexec('echo hello');",
    );
}

// T-045: no-use-effect (useEffect call in .tsx)
#[test]
fn no_use_effect_fires_on_useeffect_call() {
    assert_rule_fires(
        "no-use-effect",
        "/src/components/App.tsx",
        "import { useEffect } from 'react';\nexport const App = () => {\n  useEffect(() => {}, []);\n  return null;\n};",
    );
}

// T-046: no-use-effect silent on effect-free component
#[test]
fn no_use_effect_silent_on_effect_free_component() {
    assert_rule_silent(
        "no-use-effect",
        "/src/components/App.tsx",
        "export const App = () => {\n  const x = 1;\n  return <div>{x}</div>;\n};",
    );
}

// T-047: bidi-characters (Unicode bidi control char in source)
#[test]
fn bidi_characters_fires_on_rlo_in_source() {
    assert_rule_fires(
        "bidi-characters",
        "/src/app.ts",
        "const name = \"admin\u{202E}slim\";",
    );
}

// T-048: bidi-characters silent on plain ASCII source
#[test]
fn bidi_characters_silent_on_plain_source() {
    assert_rule_silent("bidi-characters", "/src/app.ts", "const name = \"admin\";");
}

// T-049: unsafe-regex (nested quantifier regex literal)
#[test]
fn unsafe_regex_fires_on_nested_quantifier() {
    assert_rule_fires("unsafe-regex", "/src/parse.ts", "const re = /(a+)+$/;");
}

// T-050: unsafe-regex silent on flat regex
#[test]
fn unsafe_regex_silent_on_flat_pattern() {
    assert_rule_silent("unsafe-regex", "/src/parse.ts", "const re = /^abc$/;");
}

// T-051: non-literal-require (require(nonliteral) in server context)
#[test]
fn non_literal_require_fires_in_app_api() {
    assert_rule_fires(
        "non-literal-require",
        "/app/api/route.ts",
        "const mod = require(userInput);",
    );
}

// T-052: non-literal-require silent on literal require
#[test]
fn non_literal_require_silent_on_literal() {
    assert_rule_silent(
        "non-literal-require",
        "/app/api/route.ts",
        "const fs = require('fs');",
    );
}

// T-053: env-var-fallback (sensitive env var || string-literal fallback)
#[test]
fn env_var_fallback_fires_on_api_key_default() {
    assert_rule_fires(
        "env-var-fallback",
        "/src/config.ts",
        "const key = process.env.API_KEY || 'dev-default-key';",
    );
}

// T-054: env-var-fallback silent on non-sensitive env var
#[test]
fn env_var_fallback_silent_on_log_level() {
    assert_rule_silent(
        "env-var-fallback",
        "/src/config.ts",
        "const level = process.env.LOG_LEVEL || 'info';",
    );
}

// T-055: prototype-pollution (__proto__ assignment)
#[test]
fn prototype_pollution_fires_on_proto_assignment() {
    assert_rule_fires(
        "prototype-pollution",
        "/src/obj.ts",
        "function setProto(target) {\n  target.__proto__ = source;\n}",
    );
}

// T-056: prototype-pollution silent on normal property assignment
#[test]
fn prototype_pollution_silent_on_normal_property() {
    assert_rule_silent(
        "prototype-pollution",
        "/src/obj.ts",
        "function setName(target) {\n  target.name = 'x';\n}",
    );
}

// T-057: math-random-insecure (Math.random in token context)
#[test]
fn math_random_insecure_fires_on_token_context() {
    assert_rule_fires(
        "math-random-insecure",
        "/src/token.ts",
        "const token = Math.random().toString(36).slice(2);",
    );
}

// T-058: math-random-insecure silent on Math.random assigned to a
// non-security-named identifier (verifies the security-context keyword
// discriminator, not just absence of Math.random).
#[test]
fn math_random_insecure_silent_on_non_security_identifier() {
    assert_rule_silent(
        "math-random-insecure",
        "/src/animation.ts",
        "const animationProgress = Math.random();",
    );
}

// T-059: cot-leakage-marker (Claude thinking tag in content).
// Hex-escape the 'i' in <thinking> so the Rust source does not carry the
// literal marker (file_pattern = RE_ALL_FILES would otherwise flag this
// file on the next guardrails scan). The escape expands to "<thinking>"
// at runtime, which the rule still matches.
#[test]
fn cot_leakage_marker_fires_on_thinking_tag() {
    assert_rule_fires(
        "cot-leakage-marker",
        "/src/log.ts",
        "const msg = `<th\x69nking>reasoning here</th\x69nking>`;",
    );
}

// T-060: cot-leakage-marker silent on plain content
#[test]
fn cot_leakage_marker_silent_on_plain_content() {
    assert_rule_silent(
        "cot-leakage-marker",
        "/src/log.ts",
        "const msg = 'plain log message';",
    );
}

// T-061: sqli-concat (template literal with SQL keyword + interpolation passed to call)
#[test]
fn sqli_concat_fires_on_template_interpolation() {
    assert_rule_fires(
        "sqli-concat",
        "/src/db.ts",
        "db.execute(`SELECT * FROM users WHERE id = ${userId}`);",
    );
}

// T-062: sqli-concat silent on prepared statement with placeholder
#[test]
fn sqli_concat_silent_on_prepared_statement() {
    assert_rule_silent(
        "sqli-concat",
        "/src/db.ts",
        "db.execute('SELECT * FROM users WHERE id = ?', [userId]);",
    );
}

// T-063: cors-wildcard (cors({ origin: '*' }) in api/middleware)
#[test]
fn cors_wildcard_fires_on_origin_star() {
    assert_rule_fires(
        "cors-wildcard",
        "/app/api/route.ts",
        "import cors from 'cors';\napp.use(cors({ origin: '*' }));",
    );
}

// T-064: cors-wildcard silent on specific origin
#[test]
fn cors_wildcard_silent_on_specific_origin() {
    assert_rule_silent(
        "cors-wildcard",
        "/app/api/route.ts",
        "import cors from 'cors';\napp.use(cors({ origin: 'https://example.com' }));",
    );
}

// T-065: naming-convention (lowercase interface name)
#[test]
fn naming_convention_fires_on_lowercase_interface() {
    assert_rule_fires(
        "naming-convention",
        "/src/types.ts",
        "interface user { name: string; }",
    );
}

// T-066: naming-convention silent on PascalCase interface
#[test]
fn naming_convention_silent_on_pascal_interface() {
    assert_rule_silent(
        "naming-convention",
        "/src/types.ts",
        "interface User { name: string; }",
    );
}

// T-067: architecture (utils importing components is a layer violation)
#[test]
fn architecture_fires_on_utils_importing_components() {
    assert_rule_fires(
        "architecture",
        "/src/utils/format.ts",
        "import { Button } from '../components/Button';",
    );
}

// T-068: architecture silent on valid layer dependency
#[test]
fn architecture_silent_on_pages_importing_components() {
    assert_rule_silent(
        "architecture",
        "/src/pages/Home.tsx",
        "import { Button } from '../components/Button';",
    );
}

// T-069: service-worker-scope-root (explicit root scope register)
#[test]
fn service_worker_scope_root_fires_on_explicit_root_scope() {
    assert_rule_fires(
        "service-worker-scope-root",
        "/src/sw-register.ts",
        "navigator.serviceWorker.register('/sw.js', { scope: '/' });",
    );
}

// T-070: service-worker-scope-root silent on omitted scope
#[test]
fn service_worker_scope_root_silent_on_omitted_scope() {
    assert_rule_silent(
        "service-worker-scope-root",
        "/src/sw-register.ts",
        "navigator.serviceWorker.register('/sw.js');",
    );
}

// T-071: jwt-client-decode (jwtDecode function call)
#[test]
fn jwt_client_decode_fires_on_jwtdecode_call() {
    assert_rule_fires(
        "jwt-client-decode",
        "/src/auth.ts",
        "const decoded = jwtDecode(token);",
    );
}

// T-072: jwt-client-decode silent on jwtVerify
#[test]
fn jwt_client_decode_silent_on_jwtverify() {
    assert_rule_silent(
        "jwt-client-decode",
        "/src/auth.ts",
        "const { payload } = await jwtVerify(token, secret);",
    );
}

// T-073: client-env-public-leak (use client + non-NEXT_PUBLIC env access)
#[test]
fn client_env_public_leak_fires_on_secret_in_client_component() {
    assert_rule_fires(
        "client-env-public-leak",
        "/src/components/Profile.tsx",
        "\"use client\";\nconst apiKey = process.env.SECRET_API_KEY;",
    );
}

// T-074: client-env-public-leak silent on NEXT_PUBLIC_ prefix
#[test]
fn client_env_public_leak_silent_on_next_public_prefix() {
    assert_rule_silent(
        "client-env-public-leak",
        "/src/components/Profile.tsx",
        "\"use client\";\nconst apiUrl = process.env.NEXT_PUBLIC_API_URL;",
    );
}

// T-075: ssr-secret-bleed (getServerSideProps returning props with secret env)
#[test]
fn ssr_secret_bleed_fires_on_env_secret_in_get_server_side_props() {
    assert_rule_fires(
        "ssr-secret-bleed",
        "/pages/dashboard.tsx",
        "export async function getServerSideProps() {\n  return { props: { apiKey: process.env.SECRET_API_KEY } };\n}",
    );
}

// T-076: ssr-secret-bleed silent when no secret keyword
#[test]
fn ssr_secret_bleed_silent_on_safe_props() {
    assert_rule_silent(
        "ssr-secret-bleed",
        "/pages/dashboard.tsx",
        "export async function getServerSideProps() {\n  return { props: { username: 'alice', itemCount: 3 } };\n}",
    );
}

// T-077: postmessage-origin-missing (message listener without origin validation)
#[test]
fn postmessage_origin_missing_fires_on_message_listener_without_origin() {
    assert_rule_fires(
        "postmessage-origin-missing",
        "/src/page.ts",
        "window.addEventListener('message', (event) => { processData(event.data); });",
    );
}

// T-078: postmessage-origin-missing silent when handler reads event.origin
#[test]
fn postmessage_origin_missing_silent_on_origin_guarded_listener() {
    assert_rule_silent(
        "postmessage-origin-missing",
        "/src/page.ts",
        "window.addEventListener('message', (event) => { if (event.origin !== 'https://trusted.example.com') return; processData(event.data); });",
    );
}

// T-425: hooks ファイルの非 hook helper が blocking されないことを実バイナリで見る。
// 誤検知は exit 2 として現れていたため、rule 単体の検査とは別に end-to-end で固定する。
#[test]
fn naming_convention_silent_on_hooks_file_with_non_hook_helper() {
    assert_rule_silent(
        "naming-convention",
        "/src/hooks/useFetch.ts",
        "const useFetch = () => { const [d] = useState(null); return d; };\nconst formatData = (input) => { return input.trim(); };",
    );
}

// T-080: oxlint/eslint(no-new-func) fires on `new Function(...)` (DEFAULT_DENY_RULES wired end-to-end)
#[test]
fn oxlint_no_new_func_fires_on_new_function_ctor() {
    assert_rule_fires(
        "oxlint/eslint(no-new-func)",
        "/src/app.ts",
        "const fn = new Function('return 1');",
    );
}

const RULES_OF_HOOKS: &str = "oxlint/eslint-plugin-react-hooks(rules-of-hooks)";
const REACT_MANIFEST: &str = r#"{"dependencies": {"react": "^19.0.0"}}"#;
const VUE_MANIFEST: &str = r#"{"dependencies": {"vue": "^3.5.0"}}"#;

// #424 の seam 用。`--react-plugin` の gate は編集対象の最寄り package.json を読むため、
// 他のスモークテストのような架空の path では開かない。返す `TempDir` は呼び出し側が
// 束縛したまま保持すること。捨てるとディレクトリごと消え、gate が閉じて空振りする。
fn in_project(manifest: &str) -> (tempfile::TempDir, String) {
    let root = tempfile::TempDir::new().unwrap();
    std::fs::write(root.path().join("package.json"), manifest).unwrap();
    let file_path = root
        .path()
        .join("src/hooks/useFetch.ts")
        .to_str()
        .unwrap()
        .to_owned();
    (root, file_path)
}

// T-439
#[test]
fn rules_of_hooks_fires_on_arrow_function_calling_use_state_in_react_project() {
    let (_root, path) = in_project(REACT_MANIFEST);
    assert_rule_fires(
        RULES_OF_HOOKS,
        &path,
        "import { useState } from 'react';\nexport const fetchData = () => { const [d] = useState(0); return d; };",
    );
}

// T-440
#[test]
fn rules_of_hooks_fires_on_function_declaration_calling_use_state_in_react_project() {
    let (_root, path) = in_project(REACT_MANIFEST);
    assert_rule_fires(
        RULES_OF_HOOKS,
        &path,
        "import { useState } from 'react';\nexport function fetchData() { const [d] = useState(null); return d; }",
    );
}

// T-441
#[test]
fn rules_of_hooks_fires_on_arrow_function_returning_object_holding_use_state_in_react_project() {
    let (_root, path) = in_project(REACT_MANIFEST);
    assert_rule_fires(
        RULES_OF_HOOKS,
        &path,
        "import { useState } from 'react';\nexport const fetchData = () => ({ d: useState(null) });",
    );
}

// T-442: Vue/Nuxt の composable は .ts に住むので、拡張子では切り分けられない。
#[test]
fn rules_of_hooks_silent_on_same_code_in_project_without_react_dependency() {
    let (_root, path) = in_project(VUE_MANIFEST);
    assert_rule_silent(
        RULES_OF_HOOKS,
        &path,
        "import { useState } from 'react';\nexport const fetchData = () => { const [d] = useState(0); return d; };",
    );
}

// T-443: 未知フラグを渡すと oxlint は exit 1 で JSON を出さず、rules-of-hooks
// だけでなく既存の oxlint 診断も全て消える。同一 content・同一 invocation で
// 両方を assert することだけがこの経路を捕まえる。
#[test]
fn reports_both_rules_of_hooks_and_no_console_for_one_react_project_file() {
    let (_root, path) = in_project(REACT_MANIFEST);
    let content = "import { useState } from 'react';\nexport const fetchData = () => { const [d] = useState(0); console.log(d); return d; };";
    let output = run_guardrails_json(hook_input(&path, content).as_bytes());
    let envelope = parse_envelope(&output);
    // no-console を先に見る。フラグ拒否は全診断を消すので、先に落ちたほうが
    // 「既存の診断まで消えた」という失敗の形を直接示す。
    for rule in ["oxlint/eslint(no-console)", RULES_OF_HOOKS] {
        assert!(
            !violations_for_rule(&envelope, rule).is_empty(),
            "expected {rule} in the same run that enables the react plugin; \
             an oxlint that rejects the flag exits 1 and drops every diagnostic. \
             envelope: {envelope}"
        );
    }
}
