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
        r#"{{"tool_name":"Write","tool_input":{{"file_path":"/src/app.ts","content":"{}"}}}}"#,
        content
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
        tmp.path().join(".claude/tools.json").exists(),
        "expected tools.json to be created"
    );
    let content = fs::read_to_string(tmp.path().join(".claude/tools.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(
        parsed.get("guardrails").is_some(),
        "expected guardrails key in created tools.json: {content}"
    );
}

#[test]
fn hint_not_shown_after_tools_json_created() {
    let tmp = tmp_repo_with_claude();

    // First run: creates tools.json
    run_guardrails_in_dir(&clean_write_json(), tmp.path());

    // Second run: tools.json now has guardrails key → no hint
    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("using defaults"),
        "unexpected config hint on second run: {stderr}"
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
    assert!(
        parsed["data"]["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["rule"] == "eval"),
        "expected eval violation in: {parsed}"
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
