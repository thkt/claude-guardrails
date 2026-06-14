use crate::common::{run_guardrails, run_guardrails_json};

#[test]
fn clean_code_exits_zero() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "export function main() {}\n"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn violation_exits_two() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BLOCKED"), "expected BLOCKED in: {stderr}");
}

#[test]
fn pipe_stderr_omits_ansi_escape() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('\x1b'),
        "stderr captured via pipe must not contain ANSI escape (got: {stderr:?})"
    );
}

#[test]
fn invalid_json_exits_input_error() {
    let output = run_guardrails_json("not json");
    assert_eq!(
        output.status.code(),
        Some(64),
        "expected 64 for invalid hook JSON; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unsupported_tool_exits_zero() {
    let json = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "echo hi"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn non_js_file_skips_js_rules() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/README.md",
            "content": "eval(userInput);"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn oversized_input_exits_input_error() {
    let content = "x".repeat(10_000_000);
    let json = format!(
        r#"{{"tool_name":"Write","tool_input":{{"file_path":"/src/app.ts","content":"{content}"}}}}"#
    );
    let output = run_guardrails(json.as_bytes());
    assert_eq!(
        output.status.code(),
        Some(64),
        "expected 64 for oversized hook input; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("input too large"),
        "expected size error in: {stderr}"
    );
}

#[test]
fn write_missing_content_exits_zero_with_warning() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing or empty"),
        "expected warning in: {stderr}"
    );
}

#[test]
fn unknown_tool_with_content_warns() {
    let json = serde_json::json!({
        "tool_name": "Patch",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "const x = 1;"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown tool"),
        "expected unknown tool warning in: {stderr}"
    );
}

#[test]
fn warning_only_exits_advisory_with_stderr() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/App.tsx",
            "content": "const el = document.getElementById('foo');\nexport default el;\n"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected 1 (warning only) when there are no blocking violations; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning") || stderr.contains("⚠"),
        "expected warning in stderr: {stderr}"
    );
}

// #294 regression: check_bidi (Trojan-Source detection) is a pure byte scan
// that must run independent of oxc parse success. An unterminated string makes
// the parser panic, so `with_parsed_program` returns None; before the fix that
// skipped check_bidi entirely, letting a bidi control char through (fail-open).
#[test]
fn bidi_char_blocked_even_when_parse_fails() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "const x = \"\u{202E}\nfoo"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected 2 (bidi must block despite parse failure); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bidi-characters"),
        "expected bidi-characters in stderr: {stderr}"
    );
}

// F-008 gap 3: a blocking violation (eval, High) and an advisory violation
// (dom-access, Medium) emitted together must produce exit 2, not 1.
#[test]
fn blocking_violation_takes_precedence_over_advisory() {
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/App.tsx",
            "content": "const el = document.getElementById('foo');\neval(userInput);\n"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected 2 (blocking) when blocking + advisory coexist; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BLOCKED"),
        "expected BLOCKED in stderr: {stderr}"
    );
}
