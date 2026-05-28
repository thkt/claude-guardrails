// Shared helpers for the CLI integration tests. Each `tests/cli_*.rs` file is a
// separate test crate that pulls this in via `mod common;` and uses a subset of
// the helpers, so unused-in-one-crate items are expected.
#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub fn run_guardrails_with(
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

pub fn run_guardrails(input: &[u8]) -> Output {
    run_guardrails_with(input, None, &[], &[])
}

pub fn run_guardrails_json(json: &str) -> Output {
    run_guardrails(json.as_bytes())
}

pub fn run_guardrails_with_args(input: &[u8], args: &[&str]) -> Output {
    run_guardrails_with(input, None, &[], args)
}

pub fn run_guardrails_in_dir(json: &str, dir: &Path) -> Output {
    run_guardrails_with(json.as_bytes(), Some(dir), &[("NO_COLOR", "1")], &[])
}

pub fn tmp_repo() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::create_dir(tmp.path().join(".git")).unwrap();
    tmp
}

pub fn tmp_repo_with_claude() -> tempfile::TempDir {
    let tmp = tmp_repo();
    fs::create_dir(tmp.path().join(".claude")).unwrap();
    tmp
}

pub fn clean_write_json() -> String {
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
pub const OXLINT_VERSION: &str = "1.56.0";
