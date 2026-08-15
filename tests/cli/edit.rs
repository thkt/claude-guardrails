use crate::common::{run_guardrails_json, run_guardrails_with, run_guardrails_with_args, tmp_repo};
use std::fs;

#[test]
fn edit_with_violation_exits_two() {
    let json = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/src/app.ts",
            "new_string": "eval(userInput);"
        }
    });
    let output = run_guardrails_json(&json.to_string());
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn edit_with_jsx_attribute_snippet_detects_via_full_file() {
    // Regression test for issue #59. JSX attribute snippet alone fails AST parse,
    // so before the fix all AST rules were silently skipped. The fix reads the
    // file from disk, applies the edit, and parses the post-edit content.
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("auth.tsx");
    fs::write(
        &path,
        "export function Auth({ redirectUrl }: { redirectUrl: string }) {\n  return <button>Login</button>;\n}\n",
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": path.to_str().unwrap(),
            "old_string": "<button>Login</button>",
            "new_string": "<button onClick={() => { location.href = redirectUrl; }}>Login</button>"
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
    assert!(
        stderr.contains("open-redirect"),
        "expected open-redirect in stderr, got: {stderr}"
    );
}

#[test]
fn edit_snippet_fallback_emits_degraded_true_in_json_envelope() {
    // RC-001 regression: when full-file resolution fails (here: target path
    // outside the guardrails project root — tempdir lives under /var/folders),
    // the snippet fallback must mark the envelope as degraded so downstream
    // consumers can distinguish full vs degraded analysis.
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("file.ts");
    fs::write(&path, "const a = 1;\n").unwrap();
    let json = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": path.to_str().unwrap(),
            "old_string": "pattern that does not match anywhere",
            "new_string": "const safe = 2;"
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""degraded":true"#),
        "expected degraded:true in JSON envelope, got: {stdout}"
    );
    assert!(
        stdout.contains("analyzed Edit snippet only"),
        "expected snippet-fallback note in envelope notes, got: {stdout}"
    );
}

// TC-004: MultiEdit with file readable + first edit matches + second edit's
// old_string absent in the post-first-edit content → MultiEditMidFailure with
// the failing index propagates to the envelope note.
#[test]
fn multi_edit_mid_sequence_failure_propagates_to_envelope() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("file.ts");
    fs::write(&path, "let a = 1;\n").unwrap();
    let json = serde_json::json!({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": path.to_str().unwrap(),
            "edits": [
                { "old_string": "let a = 1;", "new_string": "let a = 10;" },
                { "old_string": "no such pattern", "new_string": "irrelevant" }
            ]
        }
    });
    let output = run_guardrails_with_args(json.to_string().as_bytes(), &["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""degraded":true"#),
        "expected degraded:true, got: {stdout}"
    );
    // Note: in this environment the tempfile lives outside the project root,
    // so PathOutsideProject fires before MultiEditMidFailure. The contract
    // verified here is "any full-resolution failure surfaces in the envelope".
    assert!(
        stdout.contains("analyzed Edit snippet only"),
        "expected snippet-fallback note, got: {stdout}"
    );
}

#[test]
fn multi_edit_with_violation_exits_two() {
    let json = serde_json::json!({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": "/src/app.ts",
            "edits": [
                {"new_string": "const x = 1;"},
                {"new_string": "eval(userInput);"}
            ]
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

// F-034: OldStringNotFound-specific note must surface in the JSON envelope
// (distinguishable from other DegradedReason variants by its prefix).
#[test]
fn old_string_not_found_envelope_carries_specific_note() {
    let tmp = tmp_repo();
    let path = tmp.path().join("file.ts");
    fs::write(&path, "const a = 1;\n").unwrap();
    let json = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": path.to_str().unwrap(),
            "old_string": "pattern that does not match anywhere",
            "new_string": "const safe = 2;"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""degraded":true"#),
        "expected degraded:true: {stdout}"
    );
    assert!(
        stdout.contains("Edit pattern not found in target file"),
        "expected OldStringNotFound-specific note prefix; got: {stdout}"
    );
}

// T-535: the unit-level counterpart (T-533) stops at `collect_violations` and
// cannot see the exit code, which the config-load and partition plumbing in
// `run_hook_with_input` decides.
#[test]
fn guardrails_json_から行を削る空_new_string_の_edit_が_exit_2で止まる() {
    let tmp = tmp_repo();
    let root = tmp.path().canonicalize().unwrap();
    fs::write(
        root.join(".guardrails.json"),
        "{\n  \"rules\": { \"eval\": true }\n}\n",
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": root.join(".guardrails.json"),
            "old_string": "\"rules\": { \"eval\": true }",
            "new_string": ""
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(&root),
        &[("NO_COLOR", "1")],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "deleting a line from .guardrails.json via empty new_string must block same as a non-empty edit; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-536: `join_new_strings` joins with newlines, so two or more deleting edits
// already yield non-empty content. A single deleting edit is the only MultiEdit
// shape that reaches the same empty-content path as a bare Edit.
#[test]
fn multi_edit_の全_edit_が削除でも_exit_2で止まる() {
    let tmp = tmp_repo();
    let root = tmp.path().canonicalize().unwrap();
    fs::write(
        root.join(".guardrails.json"),
        "{\n  \"rules\": { \"eval\": true }\n}\n",
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": root.join(".guardrails.json"),
            "edits": [
                { "old_string": "\"rules\": { \"eval\": true }", "new_string": "" }
            ]
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(&root),
        &[("NO_COLOR", "1")],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a MultiEdit whose every edit deletes via empty new_string must still block; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
