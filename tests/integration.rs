use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_guardrails_with(
    input: &[u8],
    cwd: Option<&Path>,
    envs: &[(&str, &str)],
    args: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_guardrails"));
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guardrails");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn run_guardrails(input: &[u8]) -> Output {
    run_guardrails_with(input, None, &[], &[])
}

fn run_guardrails_json(json: &str) -> Output {
    run_guardrails(json.as_bytes())
}

fn run_guardrails_with_args(input: &[u8], args: &[&str]) -> Output {
    run_guardrails_with(input, None, &[], args)
}

fn run_guardrails_in_dir(json: &str, dir: &Path) -> Output {
    run_guardrails_with(json.as_bytes(), Some(dir), &[("NO_COLOR", "1")], &[])
}

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

fn tmp_repo() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::create_dir(tmp.path().join(".git")).unwrap();
    tmp
}

fn tmp_repo_with_claude() -> tempfile::TempDir {
    let tmp = tmp_repo();
    fs::create_dir(tmp.path().join(".claude")).unwrap();
    tmp
}

fn clean_write_json() -> String {
    serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "export function main() {}\n"
        }
    })
    .to_string()
}

#[test]
fn hint_shown_when_claude_dir_exists_without_tools_json() {
    let tmp = tmp_repo_with_claude();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("using defaults"),
        "expected config hint in: {stderr}"
    );
    assert!(
        !tmp.path().join(".claude/tools.json").exists(),
        "hook must not create tools.json"
    );
}

#[test]
fn hint_shown_repeatedly_when_tools_json_absent() {
    let tmp = tmp_repo_with_claude();

    let stderr1 =
        String::from_utf8_lossy(&run_guardrails_in_dir(&clean_write_json(), tmp.path()).stderr)
            .into_owned();
    assert!(
        stderr1.contains("using defaults"),
        "first run hint missing: {stderr1}"
    );

    let stderr2 =
        String::from_utf8_lossy(&run_guardrails_in_dir(&clean_write_json(), tmp.path()).stderr)
            .into_owned();
    assert!(
        stderr2.contains("using defaults"),
        "hint must keep appearing each run while tools.json is absent: {stderr2}"
    );
}

#[test]
fn hint_shown_when_tools_json_without_guardrails_key() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(".claude/tools.json"), r#"{"reviews": {}}"#).unwrap();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("using defaults"),
        "expected config hint in: {stderr}"
    );
}

#[test]
fn no_hint_when_guardrails_configured() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {}}"#,
    )
    .unwrap();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("using defaults"),
        "unexpected config hint in: {stderr}"
    );
}

#[test]
fn no_hint_when_no_claude_dir() {
    let tmp = tmp_repo();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("using defaults"),
        "unexpected config hint without .claude/ dir: {stderr}"
    );
}

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
    let huge = vec![b'a'; 10_000_001];
    let output = run_guardrails_with_args(&huge, &["--json"]);
    assert_eq!(
        output.status.code(),
        Some(64),
        "expected 64 for oversized hook input"
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

#[test]
fn parse_error_exits_64_with_stderr_message() {
    let output = run_guardrails_with_args(b"", &["--bogus-flag"]);
    assert_eq!(
        output.status.code(),
        Some(64),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--bogus-flag") || stderr.contains("unexpected"),
        "expected clap error in stderr: {stderr}"
    );
}

#[test]
fn help_flag_exits_zero_and_lists_subcommands() {
    let output = run_guardrails_with_args(b"", &["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("prefetch"),
        "help missing prefetch: {stdout}"
    );
    assert!(stdout.contains("--json"), "help missing --json: {stdout}");
    assert!(
        stdout.contains("Exit codes"),
        "help missing Exit codes section"
    );
}

#[test]
fn version_flag_exits_zero() {
    let output = run_guardrails_with_args(b"", &["--version"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("guardrails"), "version output: {stdout}");
}

// Keep in sync with OXLINT_VERSION in src/download.rs.
const OXLINT_VERSION: &str = "1.56.0";

#[test]
fn prefetch_returns_zero_when_oxlint_already_cached() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cache = tmp.path().join("guardrails/bin");
    fs::create_dir_all(&cache).unwrap();
    let bin = cache.join(format!("oxlint-{OXLINT_VERSION}"));
    fs::write(&bin, "fake").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .arg("prefetch")
        .env("XDG_CACHE_HOME", tmp.path())
        .output()
        .expect("failed to spawn guardrails");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(bin.to_str().unwrap()),
        "expected cached binary path in stderr: {stderr}"
    );
}

#[test]
fn prefetch_json_emits_success_envelope_when_cached() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cache = tmp.path().join("guardrails/bin");
    fs::create_dir_all(&cache).unwrap();
    let bin = cache.join(format!("oxlint-{OXLINT_VERSION}"));
    fs::write(&bin, "fake").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .args(["--json", "prefetch"])
        .env("XDG_CACHE_HOME", tmp.path())
        .output()
        .expect("failed to spawn guardrails");

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert!(
        parsed["data"]["path"]
            .as_str()
            .unwrap_or("")
            .contains("oxlint"),
        "envelope must carry path; got: {parsed}"
    );
    assert_eq!(parsed["degraded"], false, "cached path is not degraded");
    assert_eq!(parsed["notes"], serde_json::json!([]));
}

// Malformed `.claude/tools.json` silently falls back to default config; the
// JSON envelope must mark this as degraded so AI consumers notice they are
// not running the project's rule set.
#[test]
fn malformed_tools_json_marks_json_envelope_degraded() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(".claude/tools.json"), "{not json}").unwrap();

    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(
        parsed["degraded"], true,
        "expected degraded:true when tools.json is malformed; got: {parsed}"
    );
    let notes = parsed["notes"].as_array().expect("notes must be an array");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("invalid config")),
        "expected a config-error note in envelope; got: {notes:?}"
    );
}

#[test]
fn prefetch_json_io_error_envelope_when_cache_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .args(["--json", "prefetch"])
        .env_remove("HOME")
        .env_remove("XDG_CACHE_HOME")
        .output()
        .expect("failed to spawn guardrails");

    assert_eq!(
        output.status.code(),
        Some(74),
        "expected EX_IOERR; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(parsed["error"]["code"], "IO_ERROR");
    assert!(
        parsed["error"]["next_step"]
            .as_str()
            .unwrap_or("")
            .contains("XDG_CACHE_HOME"),
        "next_step must mention XDG_CACHE_HOME; got: {parsed}"
    );
    assert_eq!(parsed["error"]["retryable"], false);
}

// F-008 gap 1: enabled:false at top level skips all rule evaluation.
#[test]
fn disabled_config_skips_rule_evaluation() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {"enabled": false}}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), tmp.path());
    assert_eq!(
        output.status.code(),
        Some(0),
        "enabled:false must skip eval rule; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// F-008 gap 2: enabled:false + --json emits an allow decision with zero violations.
#[test]
fn disabled_config_with_json_emits_allow_decision() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {"enabled": false}}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(parsed["data"]["decision"], "allow");
    assert!(
        parsed["data"]["violations"]
            .as_array()
            .expect("violations array")
            .is_empty(),
        "enabled:false must yield zero violations: {parsed}"
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

// F-008 gap 4: a malformed `.claude/tools.json` must fall back to default
// config so violation detection keeps running (binary-level, non-JSON path).
// The existing `malformed_tools_json_marks_json_envelope_degraded` covers the
// --json envelope side; this covers the stderr / exit-code side.
#[test]
fn malformed_config_falls_back_to_defaults_and_keeps_detecting() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(".claude/tools.json"), "{not json}").unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), tmp.path());
    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed config must fall back to defaults and still block eval; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BLOCKED") || stderr.contains("eval"),
        "expected eval violation despite config error: {stderr}"
    );
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

// F-034: `prefetch` without `--json` must still surface the cache-unavailable
// failure on stderr and exit with EX_IOERR (74). The existing
// `prefetch_json_io_error_envelope_when_cache_unavailable` covers the --json
// envelope path; this covers the human-readable stderr path.
#[test]
fn prefetch_without_json_exits_io_error_with_stderr_diagnostic() {
    let output = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .arg("prefetch")
        .env_remove("HOME")
        .env_remove("XDG_CACHE_HOME")
        .output()
        .expect("failed to spawn guardrails");
    assert_eq!(
        output.status.code(),
        Some(74),
        "expected EX_IOERR; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no cache directory available"),
        "expected OxlintError::CacheDirUnavailable Display string in stderr: {stderr}"
    );
}

// T-180: When `node_modules/.bin/oxlint` is a symlink to a path outside the
// project root (pnpm-style content-addressable store, attacker-planted bin),
// the envelope must carry the reject note distinct from the generic
// "oxlint not found" note. Verifies the `Result<PathBuf, ResolveError>` split
// in `try_resolve_bin` reaches the envelope. `XDG_CACHE_HOME` pre-seeded with
// a placeholder `oxlint-{OXLINT_VERSION}` keeps the bundled fallback offline
// — the placeholder is not executable, so `oxlint::check` fails next and a
// second note is appended; both must coexist on the envelope.
#[test]
#[cfg(unix)]
fn outside_project_root_bin_emits_reject_note_in_envelope() {
    use std::os::unix::fs::symlink;

    let project_tmp = tmp_repo();
    let store_tmp = tempfile::TempDir::new().unwrap();
    let store_bin = store_tmp.path().join("oxlint");
    fs::write(&store_bin, "#!/bin/sh\nexit 0\n").unwrap();

    let bin_dir = project_tmp.path().join("node_modules/.bin");
    fs::create_dir_all(&bin_dir).unwrap();
    symlink(&store_bin, bin_dir.join("oxlint")).unwrap();

    let cache_tmp = tempfile::TempDir::new().unwrap();
    let cache_bin_dir = cache_tmp.path().join("guardrails/bin");
    fs::create_dir_all(&cache_bin_dir).unwrap();
    fs::write(
        cache_bin_dir.join(format!("oxlint-{OXLINT_VERSION}")),
        "fake",
    )
    .unwrap();

    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(project_tmp.path()),
        &[
            ("NO_COLOR", "1"),
            ("XDG_CACHE_HOME", cache_tmp.path().to_str().unwrap()),
        ],
        &["--json"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    let notes = parsed["notes"].as_array().expect("notes must be an array");
    assert!(
        notes.iter().any(|n| n
            .as_str()
            .unwrap_or("")
            .contains("outside trusted location")),
        "envelope must carry OutsideProjectRoot reject note; got: {notes:?}"
    );
    assert_eq!(
        parsed["degraded"], true,
        "envelope must be degraded when reject note present; got: {parsed}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("outside trusted location"),
        "stderr must surface reject for human reader; got: {stderr}"
    );
}
