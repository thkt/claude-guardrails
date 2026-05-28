mod common;

use common::{run_guardrails_with, run_guardrails_with_args, tmp_repo, OXLINT_VERSION};
use std::fs;
use std::process::Command;

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
