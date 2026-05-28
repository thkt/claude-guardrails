use crate::parse_json::parse_linter_json;
use crate::temp_file::write_temp;
use serde::de::DeserializeOwned;
use std::any::Any;
use std::fs;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const LINTER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum WaitOutcome {
    Exited(ExitStatus),
    ProcessError(io::Error),
    Timeout,
    WaitThreadPanic,
}

fn classify_wait(result: Result<io::Result<ExitStatus>, RecvTimeoutError>) -> WaitOutcome {
    match result {
        Ok(Ok(status)) => WaitOutcome::Exited(status),
        Ok(Err(e)) => WaitOutcome::ProcessError(e),
        Err(RecvTimeoutError::Timeout) => WaitOutcome::Timeout,
        Err(RecvTimeoutError::Disconnected) => WaitOutcome::WaitThreadPanic,
    }
}

fn format_thread_panic(payload: Box<dyn Any + Send>) -> String {
    let payload = match payload.downcast::<&'static str>() {
        Ok(s) => return (*s).to_owned(),
        Err(p) => p,
    };
    match payload.downcast::<String>() {
        Ok(s) => *s,
        Err(_) => "<non-string panic payload>".into(),
    }
}

fn spawn_pipe_reader(
    pipe: impl Read + Send + 'static,
    tool: &'static str,
    label: &'static str,
) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut pipe = pipe;
        let mut buf = Vec::new();
        if let Err(e) = pipe.read_to_end(&mut buf) {
            eprintln!("guardrails: {tool}: {label} read error: {e}");
        }
        buf
    })
}

fn kill_pid(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn wait_with_timeout(child: Child, tool: &'static str) -> Option<ExitStatus> {
    let child_pid = child.id();
    let (tx, rx) = mpsc::channel();
    let wait_handle: JoinHandle<()> = thread::spawn(move || {
        let mut child = child;
        let _ = tx.send(child.wait());
    });

    match classify_wait(rx.recv_timeout(LINTER_TIMEOUT)) {
        WaitOutcome::Exited(s) => Some(s),
        WaitOutcome::ProcessError(e) => {
            eprintln!("guardrails: {tool}: process error: {e}");
            None
        }
        WaitOutcome::Timeout => {
            eprintln!(
                "guardrails: {}: timed out after {}s, skipping",
                tool,
                LINTER_TIMEOUT.as_secs()
            );
            kill_pid(child_pid);
            None
        }
        WaitOutcome::WaitThreadPanic => {
            let detail = match wait_handle.join() {
                Err(payload) => format_thread_panic(payload),
                Ok(()) => "<no panic payload>".into(),
            };
            eprintln!("guardrails: {tool}: wait thread panicked: {detail}");
            kill_pid(child_pid);
            None
        }
    }
}

pub fn run_with_timeout(cmd: &mut Command, tool: &'static str) -> Option<Output> {
    let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardrails: {tool}: failed to spawn: {e}");
            return None;
        }
    };

    let out_t = spawn_pipe_reader(child.stdout.take()?, tool, "stdout");
    let err_t = spawn_pipe_reader(child.stderr.take()?, tool, "stderr");

    let status = wait_with_timeout(child, tool);

    let stdout = out_t.join().unwrap_or_else(|payload| {
        eprintln!(
            "guardrails: {tool}: stdout reader thread panicked: {}",
            format_thread_panic(payload)
        );
        Vec::new()
    });
    let stderr = err_t.join().unwrap_or_else(|payload| {
        eprintln!(
            "guardrails: {tool}: stderr reader thread panicked: {}",
            format_thread_panic(payload)
        );
        Vec::new()
    });

    status.map(|s| Output {
        status: s,
        stdout,
        stderr,
    })
}

// `OutsideProjectRoot` carries the canonical path so callers can record it for
// forensics. The string is for human/log consumption only; never echo a "place
// the bin under <root>/node_modules/.bin to use it" hint anywhere downstream —
// the trust boundary is the spec, not a bypass instruction.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    #[error("no binary found in ancestor node_modules/.bin/")]
    NotFound,
    #[error("binary resolved outside trusted location: {canonical:?}")]
    OutsideProjectRoot { canonical: PathBuf },
}

/// Resolves a local `node_modules/.bin/<name>` near `file_path`.
///
/// When `project_root` is `Some`, the resolved bin must canonicalize inside
/// that root or it is rejected with `ResolveError::OutsideProjectRoot`.
/// Canonicalize the bin, not `file_path`, because Write creates files that do
/// not exist yet.
///
/// First-match-wins on the ancestor walk: a rejected closest bin returns
/// `Err(OutsideProjectRoot)` without continuing the walk, leaving fallback
/// (e.g. `ensure_oxlint`) to the caller. No PATH fallback — a globally
/// installed `oxlint` could sit outside any project root. `None` disables the
/// boundary and is reserved for tests over tempdirs.
pub fn try_resolve_bin(
    name: &str,
    file_path: &str,
    project_root: Option<&Path>,
) -> Result<PathBuf, ResolveError> {
    let canonical = Path::new(file_path)
        .ancestors()
        .skip(1) // skip the file itself, start from parent dir
        .map(|d| d.join("node_modules/.bin").join(name))
        .find_map(|c| fs::canonicalize(&c).ok())
        .ok_or(ResolveError::NotFound)?;

    if project_root.is_none_or(|root| canonical.starts_with(root)) {
        Ok(canonical)
    } else {
        Err(ResolveError::OutsideProjectRoot { canonical })
    }
}

pub fn run_linter_check<T: DeserializeOwned>(
    content: &str,
    file_path: &str,
    bin: &Path,
    args: &[&str],
    tool: &'static str,
) -> Option<T> {
    let temp_file = write_temp(content, file_path, tool)?;
    let temp_path_str = temp_file.path().to_str().or_else(|| {
        eprintln!("guardrails: {tool}: temp path contains non-UTF8 characters");
        None
    })?;

    let output = run_with_timeout(Command::new(bin).args(args).arg(temp_path_str), tool)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    parse_linter_json::<T>(&stdout, &stderr, tool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn classify_wait_exited_returns_status() {
        let status = Command::new("true").status().unwrap();
        match classify_wait(Ok(Ok(status))) {
            WaitOutcome::Exited(s) => assert!(s.success()),
            other => panic!("expected Exited, got {other:?}"),
        }
    }

    #[test]
    fn classify_wait_process_error_returns_error() {
        let err = io::Error::other("spawn failed");
        match classify_wait(Ok(Err(err))) {
            WaitOutcome::ProcessError(e) => assert!(e.to_string().contains("spawn failed")),
            other => panic!("expected ProcessError, got {other:?}"),
        }
    }

    #[test]
    fn classify_wait_timeout_distinct_from_disconnected() {
        assert!(matches!(
            classify_wait(Err(RecvTimeoutError::Timeout)),
            WaitOutcome::Timeout
        ));
        assert!(matches!(
            classify_wait(Err(RecvTimeoutError::Disconnected)),
            WaitOutcome::WaitThreadPanic
        ));
    }

    #[test]
    fn classify_wait_disconnected_observed_when_sender_dropped() {
        let (tx, rx) = mpsc::channel::<io::Result<ExitStatus>>();
        drop(tx);
        assert!(matches!(
            classify_wait(rx.recv_timeout(Duration::from_millis(10))),
            WaitOutcome::WaitThreadPanic
        ));
    }

    #[test]
    fn format_thread_panic_extracts_str_payload() {
        let payload: Box<dyn Any + Send> = Box::new("oops");
        assert_eq!(format_thread_panic(payload), "oops");
    }

    #[test]
    fn format_thread_panic_extracts_string_payload() {
        let payload: Box<dyn Any + Send> = Box::new(String::from("dynamic message"));
        assert_eq!(format_thread_panic(payload), "dynamic message");
    }

    #[test]
    fn format_thread_panic_falls_back_for_non_string_payload() {
        let payload: Box<dyn Any + Send> = Box::new(42i32);
        assert_eq!(format_thread_panic(payload), "<non-string panic payload>");
    }

    #[test]
    fn format_thread_panic_extracts_actual_thread_panic_str() {
        let handle = thread::spawn(|| panic!("thread blew up"));
        let payload = handle.join().expect_err("thread must panic");
        assert_eq!(format_thread_panic(payload), "thread blew up");
    }

    #[test]
    fn run_with_timeout_captures_stdout() {
        let output = run_with_timeout(Command::new("echo").arg("hello"), "test-echo").unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("hello"),
            "expected 'hello' in stdout, got: {stdout:?}"
        );
    }

    #[test]
    fn run_with_timeout_captures_stderr() {
        let output = run_with_timeout(
            Command::new("sh").args(["-c", "echo err >&2"]),
            "test-stderr",
        )
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("err"),
            "expected 'err' in stderr, got: {stderr:?}"
        );
    }

    #[test]
    fn run_with_timeout_returns_none_on_spawn_failure() {
        let result = run_with_timeout(
            &mut Command::new("nonexistent_binary_xyz_12345"),
            "test-missing",
        );
        assert!(result.is_none());
    }

    #[test]
    fn finds_bin_in_direct_parent_node_modules() {
        let tmp = TempDir::new().unwrap();
        let bin_dir = tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = bin_dir.join("oxlint");
        fs::write(&bin_path, "").unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let result = try_resolve_bin("oxlint", file_path.to_str().unwrap(), None);
        assert_eq!(result.unwrap(), fs::canonicalize(&bin_path).unwrap());
    }

    #[test]
    fn walks_up_to_find_node_modules() {
        let tmp = TempDir::new().unwrap();
        let bin_dir = tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = bin_dir.join("oxlint");
        fs::write(&bin_path, "").unwrap();

        let deep_dir = tmp.path().join("src/components");
        fs::create_dir_all(&deep_dir).unwrap();
        let file_path = deep_dir.join("Button.tsx");

        let result = try_resolve_bin("oxlint", file_path.to_str().unwrap(), None);
        assert_eq!(result.unwrap(), fs::canonicalize(&bin_path).unwrap());
    }

    #[test]
    fn returns_not_found_when_no_bin_exists() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.ts");

        let result = try_resolve_bin("nonexistent_tool_xyz", file_path.to_str().unwrap(), None);
        assert!(
            matches!(result, Err(ResolveError::NotFound)),
            "expected NotFound, got {result:?}"
        );
    }

    #[test]
    fn prefers_closest_node_modules() {
        let tmp = TempDir::new().unwrap();

        let root_bin = tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&root_bin).unwrap();
        fs::write(root_bin.join("oxlint"), "root").unwrap();

        let nested_bin = tmp.path().join("packages/app/node_modules/.bin");
        fs::create_dir_all(&nested_bin).unwrap();
        fs::write(nested_bin.join("oxlint"), "nested").unwrap();

        let file_path = tmp.path().join("packages/app/src/index.ts");
        let result = try_resolve_bin("oxlint", file_path.to_str().unwrap(), None);
        assert_eq!(
            result.unwrap(),
            fs::canonicalize(nested_bin.join("oxlint")).unwrap()
        );
    }

    // A planted `node_modules/.bin/<name>` outside the canonical project root
    // must not be executed even when the hook runs on a file inside that tree
    // (attacker-controlled scratch area, sibling repo, /tmp scaffold). The
    // returned variant must carry the canonical path so callers can record it.
    #[test]
    fn rejects_bin_outside_project_root() {
        let project_tmp = TempDir::new().unwrap();
        let project_root = fs::canonicalize(project_tmp.path()).unwrap();

        let attack_tmp = TempDir::new().unwrap();
        let attack_bin_dir = attack_tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&attack_bin_dir).unwrap();
        let attack_bin = attack_bin_dir.join("oxlint");
        fs::write(&attack_bin, "#!/bin/sh\nexit 0\n").unwrap();

        let file_path = attack_tmp.path().join("src/app.ts");
        let result = try_resolve_bin(
            "oxlint",
            file_path.to_str().unwrap(),
            Some(project_root.as_path()),
        );
        match result {
            Err(ResolveError::OutsideProjectRoot { canonical }) => {
                assert_eq!(canonical, fs::canonicalize(&attack_bin).unwrap());
            }
            other => panic!("expected OutsideProjectRoot, got {other:?}"),
        }
    }

    // A sibling tempdir holding a planted oxlint must not leak in when
    // file_path lives inside project_root proper — the ancestor walk never
    // reaches the sibling tree, so the outcome is `NotFound`, not a reject.
    #[test]
    fn sibling_tree_bin_not_selected_when_file_inside_root() {
        let project_tmp = TempDir::new().unwrap();
        let project_root = fs::canonicalize(project_tmp.path()).unwrap();

        let sibling_tmp = TempDir::new().unwrap();
        let sibling_bin_dir = sibling_tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&sibling_bin_dir).unwrap();
        fs::write(sibling_bin_dir.join("oxlint"), "").unwrap();

        let file_path = project_root.join("src/app.ts");
        let result = try_resolve_bin(
            "oxlint",
            file_path.to_str().unwrap(),
            Some(project_root.as_path()),
        );
        assert!(
            matches!(result, Err(ResolveError::NotFound)),
            "expected NotFound, got {result:?}"
        );
    }

    // Measure per-call cost of try_resolve_bin against an ancestor depth that
    // exceeds typical project layouts (10 levels). Used to verify whether
    // ancestor-stat work is dominant vs hook startup before adding a cache.
    // Run with: cargo test --release --bin guardrails resolve::tests::bench -- --ignored --nocapture
    #[test]
    #[ignore = "manual perf bench, run with --ignored --nocapture"]
    fn bench_try_resolve_bin_cost_per_call() {
        use std::time::Instant;

        let tmp = TempDir::new().unwrap();
        let mut dir = tmp.path().to_path_buf();
        for i in 0..10 {
            dir = dir.join(format!("d{i}"));
        }
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("file.ts");

        let iters = 1000u32;
        let start = Instant::now();
        for _ in 0..iters {
            let _ = try_resolve_bin("oxlint", file_path.to_str().unwrap(), None);
        }
        let elapsed = start.elapsed();
        let per_call_ns = elapsed.as_nanos() / u128::from(iters);
        eprintln!(
            "bench: try_resolve_bin (depth 10, all miss) {iters} iters in {elapsed:?}, \
             per call = {per_call_ns} ns ({} us)",
            per_call_ns / 1000
        );
    }

    // Legitimate `<project_root>/node_modules/.bin/` resolution still works
    // once the boundary check is in place.
    #[test]
    fn accepts_bin_inside_project_root() {
        let project_tmp = TempDir::new().unwrap();
        let project_root = fs::canonicalize(project_tmp.path()).unwrap();

        let bin_dir = project_root.join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = bin_dir.join("oxlint");
        fs::write(&bin_path, "").unwrap();

        let file_path = project_root.join("src/app.ts");
        let result = try_resolve_bin(
            "oxlint",
            file_path.to_str().unwrap(),
            Some(project_root.as_path()),
        );
        assert_eq!(result.unwrap(), fs::canonicalize(&bin_path).unwrap());
    }
}
