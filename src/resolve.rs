use crate::parse_json::parse_linter_json;
use crate::tempfile_util::write_temp;
use serde::de::DeserializeOwned;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const LINTER_TIMEOUT: Duration = Duration::from_secs(5);

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

fn wait_with_timeout(child: Child, tool: &'static str) -> Option<ExitStatus> {
    let child_pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut child = child;
        let _ = tx.send(child.wait());
    });

    match rx.recv_timeout(LINTER_TIMEOUT) {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            eprintln!("guardrails: {tool}: process error: {e}");
            None
        }
        Err(_) => {
            eprintln!(
                "guardrails: {}: timed out after {}s, skipping",
                tool,
                LINTER_TIMEOUT.as_secs()
            );
            #[cfg(unix)]
            {
                let _ = Command::new("kill")
                    .args(["-KILL", &child_pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            #[cfg(not(unix))]
            {
                let _ = Command::new("taskkill")
                    .args(["/F", "/PID", &child_pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
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

    let stdout = out_t.join().unwrap_or_else(|_| {
        eprintln!("guardrails: {tool}: stdout reader thread panicked");
        Vec::new()
    });
    let stderr = err_t.join().unwrap_or_else(|_| {
        eprintln!("guardrails: {tool}: stderr reader thread panicked");
        Vec::new()
    });

    status.map(|s| Output {
        status: s,
        stdout,
        stderr,
    })
}

/// Resolves a local `node_modules/.bin/<name>` near `file_path`.
///
/// When `project_root` is `Some`, the resolved bin must canonicalize inside
/// that root or it is rejected. Canonicalize the bin, not `file_path`, because
/// Write creates files that do not exist yet.
///
/// First-match-wins on the ancestor walk: a rejected closest bin falls through
/// to the caller's fallback (e.g. `ensure_oxlint`) rather than continuing the
/// walk. No PATH fallback — a globally installed `oxlint` could sit outside
/// any project root. `None` disables the boundary and is reserved for tests
/// over tempdirs.
pub fn try_resolve_bin(
    name: &str,
    file_path: &str,
    project_root: Option<&Path>,
) -> Option<PathBuf> {
    let canonical = Path::new(file_path)
        .ancestors()
        .skip(1) // skip the file itself, start from parent dir
        .map(|d| d.join("node_modules/.bin").join(name))
        .find_map(|c| fs::canonicalize(&c).ok())?;

    project_root
        .is_none_or(|root| canonical.starts_with(root))
        .then_some(canonical)
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
        assert_eq!(result, Some(fs::canonicalize(&bin_path).unwrap()));
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
        assert_eq!(result, Some(fs::canonicalize(&bin_path).unwrap()));
    }

    #[test]
    fn returns_none_when_not_found() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.ts");

        let result = try_resolve_bin("nonexistent_tool_xyz", file_path.to_str().unwrap(), None);
        assert_eq!(result, None);
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
            result,
            Some(fs::canonicalize(nested_bin.join("oxlint")).unwrap())
        );
    }

    // A planted `node_modules/.bin/<name>` outside the canonical project root
    // must not be executed even when the hook runs on a file inside that tree
    // (attacker-controlled scratch area, sibling repo, /tmp scaffold).
    #[test]
    fn rejects_bin_outside_project_root() {
        let project_tmp = TempDir::new().unwrap();
        let project_root = fs::canonicalize(project_tmp.path()).unwrap();

        let attack_tmp = TempDir::new().unwrap();
        let attack_bin_dir = attack_tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&attack_bin_dir).unwrap();
        fs::write(attack_bin_dir.join("oxlint"), "#!/bin/sh\nexit 0\n").unwrap();

        let file_path = attack_tmp.path().join("src/app.ts");
        let result = try_resolve_bin(
            "oxlint",
            file_path.to_str().unwrap(),
            Some(project_root.as_path()),
        );
        assert_eq!(
            result, None,
            "binary outside project_root must be rejected; got {result:?}"
        );
    }

    // A sibling tempdir holding a planted oxlint must not leak in when
    // file_path lives inside project_root proper — the ancestor walk never
    // reaches the sibling tree.
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
        assert_eq!(result, None);
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
        assert_eq!(result, Some(fs::canonicalize(&bin_path).unwrap()));
    }
}
