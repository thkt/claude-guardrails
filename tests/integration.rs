use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_guardrails(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guardrails");

    child.stdin.take().unwrap().write_all(input).unwrap();

    child.wait_with_output().unwrap()
}

fn run_guardrails_json(json: &str) -> Output {
    run_guardrails(json.as_bytes())
}

fn run_guardrails_in_dir(json: &str, dir: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guardrails");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
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
fn invalid_json_exits_one() {
    let output = run_guardrails_json("not json");
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
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
fn oversized_input_exits_two() {
    let content = "x".repeat(10_000_000);
    let json = format!(
        r#"{{"tool_name":"Write","tool_input":{{"file_path":"/src/app.ts","content":"{}"}}}}"#,
        content
    );
    let output = run_guardrails(json.as_bytes());
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
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
fn warning_only_exits_zero_with_stderr() {
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
        Some(0),
        "expected exit 0 for medium-severity-only, stderr: {}",
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
