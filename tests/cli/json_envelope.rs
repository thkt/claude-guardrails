use crate::common::{run_guardrails_json, run_guardrails_with_args};

#[test]
fn json_mode_violation_emits_block_decision() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    assert_eq!(parsed["data"]["decision"], "block");
    assert!(
        parsed["exit_code"].is_null(),
        "envelope drops top-level exit_code"
    );
    assert!(
        parsed["degraded"].is_boolean(),
        "envelope must carry a boolean degraded field; got: {parsed}"
    );
    let violations = parsed["data"]["violations"].as_array().unwrap();
    assert!(
        violations.iter().any(|v| v["rule"] == "eval"),
        "expected eval violation in: {parsed}"
    );
    assert!(
        !violations
            .iter()
            .any(|v| v["rule"] == "oxlint/eslint(no-eval)"),
        "oxlint must not also report eslint(no-eval) for the same file:line; custom `eval` rule owns the detection: {parsed}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BLOCKED"),
        "stderr must keep human-readable BLOCKED in: {stderr}"
    );
}

#[test]
fn json_mode_clean_emits_allow_decision() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "export function main() {}\n"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    assert_eq!(parsed["data"]["decision"], "allow");
    assert!(
        parsed["degraded"].is_boolean(),
        "envelope must carry a boolean degraded field; got: {parsed}"
    );
    assert!(parsed["data"]["violations"].as_array().unwrap().is_empty());
}

#[test]
fn json_mode_warning_only_keeps_allow_decision() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/App.tsx",
            "content": "const el = document.getElementById('foo');\nexport default el;\n"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected 1 (warning only) — the JSON decision field still tracks blocking violations only, so it stays 'allow'"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    assert_eq!(parsed["data"]["decision"], "allow");
    assert!(
        parsed["degraded"].is_boolean(),
        "envelope must carry a boolean degraded field; got: {parsed}"
    );
    let violations = parsed["data"]["violations"]
        .as_array()
        .expect("violations array");
    assert!(
        !violations.is_empty(),
        "expected at least one warning-level violation in: {parsed}"
    );
    assert!(
        violations
            .iter()
            .all(|v| v["severity"] != "critical" && v["severity"] != "high"),
        "expected only non-blocking severities in: {parsed}"
    );
    assert!(
        violations.iter().any(|v| v["rule"] == "dom-access"),
        "expected dom-access rule to fire for document.getElementById in .tsx: {parsed}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning") || stderr.contains("⚠"),
        "stderr must keep warning text in: {stderr}"
    );
}

// T-427 (#422): 編集を止めるかどうかは violation の severity ではなく envelope の
// decision にしか現れないため、advisory に留まることはここでしか固定できない。
#[test]
fn json_mode_naming_convention_stays_allow() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/types.ts",
            "content": "interface user { name: string; }\n"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    let violations = parsed["data"]["violations"]
        .as_array()
        .expect("violations array");
    assert!(
        violations.iter().any(|v| v["rule"] == "naming-convention"),
        "expected naming-convention to fire for a lowercase interface: {parsed}"
    );
    assert_eq!(parsed["data"]["decision"], "allow");
    assert_eq!(
        output.status.code(),
        Some(1),
        "advisory only, so the edit is not stopped: {parsed}"
    );
}

#[test]
fn json_mode_unsupported_tool_emits_allow() {
    let json = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"}
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON for allow paths");
    assert_eq!(parsed["data"]["decision"], "allow");
    assert!(
        parsed["degraded"].is_boolean(),
        "envelope must carry a boolean degraded field; got: {parsed}"
    );
    assert!(parsed["data"]["violations"].as_array().unwrap().is_empty());
}

#[test]
fn json_mode_missing_content_emits_allow() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {"file_path": "/src/app.ts"}
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON for allow paths");
    assert_eq!(parsed["data"]["decision"], "allow");
    assert!(
        parsed["degraded"].is_boolean(),
        "envelope must carry a boolean degraded field; got: {parsed}"
    );
}

#[test]
fn json_mode_invalid_json_emits_error_envelope() {
    let output = run_guardrails_with_args(b"not json", &["--json"]);
    assert_eq!(
        output.status.code(),
        Some(64),
        "expected 64 for invalid hook JSON"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(
        parsed["error"]["code"], "DATA_ERROR",
        "envelope should classify invalid JSON as DATA_ERROR; got: {parsed}"
    );
    assert!(
        parsed["error"]["next_step"].is_string(),
        "envelope should carry next_step hint; got: {parsed}"
    );
    assert_eq!(parsed["error"]["retryable"], false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid JSON"),
        "stderr must keep human-readable message in: {stderr}"
    );
}

#[test]
fn json_mode_oversized_input_emits_error_envelope() {
    // #375: oversized blocks via exit 2 (fail-closed). The ErrorEnvelope still
    // rides stdout with DATA_ERROR — only the exit code differs from 64.
    let huge = vec![b'a'; 10_000_001];
    let output = run_guardrails_with_args(&huge, &["--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected 2 (block) for oversized hook input"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(parsed["error"]["code"], "DATA_ERROR");
    assert!(
        parsed["error"]["next_step"]
            .as_str()
            .unwrap_or("")
            .contains("Reduce input size"),
        "envelope should suggest size reduction; got: {parsed}"
    );
    assert_eq!(parsed["error"]["retryable"], false);
}

#[test]
fn json_mode_disabled_without_flag() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "stdout must remain empty without --json flag, got: {stdout}"
    );
}

/// dom-access だけを踏む Write。blocking な rule には当たらない。
fn advisory_only_write() -> serde_json::Value {
    serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.tsx",
            "content": "export function App() { document.getElementById('x'); return null; }\n"
        }
    })
}

// T-520: advisory だけの Write では stdout の hook JSON に rule id が含まれる
#[test]
fn advisory_だけの_write_では_stdout_の_hook_json_に_rule_id_が含まれる() {
    let json = advisory_only_write();
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(1),
        "advisory only; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be one hook JSON document");
    assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    let context = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext must be a string");
    assert!(context.contains("dom-access"), "context: {context}");
}

// T-521: blocking を含む Write では stdout が空のままになる
#[test]
fn blocking_を含む_write_では_stdout_が空のままになる() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "the exit-2 stderr path already reaches the agent, got: {stdout}"
    );
}

// T-548: --json を付けた advisory の実行では envelope と hook JSON が同じ 1 つの
// オブジェクトに載る
#[test]
fn json_を付けた_advisory_の実行では_envelope_と_hook_json_が同居する() {
    let json = advisory_only_write();
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be one JSON document");
    assert!(parsed.get("data").is_some(), "expected envelope: {parsed}");
    assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    let context = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext must be a string");
    assert!(context.contains("dom-access"), "context: {context}");
}

// T-546: --json を付けた blocking の実行では hookSpecificOutput が載らない
#[test]
fn json_を付けた_blocking_の実行では_hookspecificoutput_が載らない() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be one JSON document");
    assert!(
        parsed.get("hookSpecificOutput").is_none(),
        "the exit-2 stderr path already reaches the agent: {parsed}"
    );
}

// T-547: --json を付けた pass の実行では hookSpecificOutput が載らない
#[test]
fn json_を付けた_pass_の実行では_hookspecificoutput_が載らない() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be one JSON document");
    assert!(
        parsed.get("hookSpecificOutput").is_none(),
        "nothing to deliver to the agent: {parsed}"
    );
}

// T-549: --json 無しの advisory の実行では stdout が hook JSON だけのままになる
#[test]
fn json_無しの_advisory_の実行では_stdout_が_hook_json_だけのままになる() {
    let json = advisory_only_write();
    let output = run_guardrails_json(&json.to_string());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be one JSON document");
    assert!(parsed.get("hookSpecificOutput").is_some(), "{parsed}");
    assert!(
        parsed.get("data").is_none(),
        "the envelope needs --json: {parsed}"
    );
}
