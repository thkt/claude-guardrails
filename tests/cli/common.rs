// Shared helpers for the CLI integration tests. Sibling submodules of the `cli`
// test crate reach these via `crate::common::*`.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub(crate) fn run_guardrails_with(
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

pub(crate) fn run_guardrails(input: &[u8]) -> Output {
    run_guardrails_with(input, None, &[], &[])
}

pub(crate) fn run_guardrails_json(json: &str) -> Output {
    run_guardrails(json.as_bytes())
}

pub(crate) fn run_guardrails_with_args(input: &[u8], args: &[&str]) -> Output {
    run_guardrails_with(input, None, &[], args)
}

pub(crate) fn run_ast_child_with_closed_stdout(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guardrails"))
        .arg("__ast-child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guardrails ast child");

    // The child blocks on stdin until after the parent closes stdout's read end,
    // so its single println deterministically writes to a pipe with no reader.
    drop(child.stdout.take().expect("ast child stdout must be piped"));
    let mut stdin = child.stdin.take().expect("ast child stdin must be piped");
    stdin.write_all(input).expect("write ast child request");
    drop(stdin);

    child.wait_with_output().expect("wait for ast child")
}

pub(crate) fn run_guardrails_in_dir(json: &str, dir: &Path) -> Output {
    run_guardrails_with(json.as_bytes(), Some(dir), &[("NO_COLOR", "1")], &[])
}

pub(crate) fn tmp_repo() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::create_dir(tmp.path().join(".git")).unwrap();
    tmp
}

pub(crate) fn tmp_repo_with_claude() -> tempfile::TempDir {
    let tmp = tmp_repo();
    fs::create_dir(tmp.path().join(".claude")).unwrap();
    tmp
}

pub(crate) fn clean_write_json() -> String {
    serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "export function main() {}\n"
        }
    })
    .to_string()
}

// Keep in sync with OXLINT_VERSION in src/download.rs.
pub(crate) const OXLINT_VERSION: &str = "1.56.0";
