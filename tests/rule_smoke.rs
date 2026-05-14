//! rule_id 単位のスモークテスト (Issue #98 受け入れ条件 #2)。
//! 各ルールについて違反 1 件 + 健全 1 件のペアを `--json` envelope の
//! `data.violations[].rule` で assert する。健全側は file_pattern が match
//! する正常コードを使い、「ルールが skip されただけ」を検出から除外する。

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run_guardrails_json(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .args(["--json"])
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("expected JSON envelope, got: {stdout}\nerror: {e}"))
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
    assert!(
        !hits.is_empty(),
        "expected at least one {rule_id} violation in {}\nstderr: {}",
        envelope,
        String::from_utf8_lossy(&output.stderr)
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
