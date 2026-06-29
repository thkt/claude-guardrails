use crate::io::parse_json::parse_linter_json;
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
///
/// Deliberate divergence from the sibling resolvers (formatter, gates), which
/// are independent copies sharing one guard skeleton: bounded depth, a `.git`
/// fence, a `$HOME` fence, and an exec-bit check. This copy adopts none of them
/// on purpose. The `canonicalize` + `project_root` boundary is a stronger
/// implementation of the same goal, and the fences would regress it: a `.git`
/// or `$HOME` fence stops the walk before an outside bin is reached, turning the
/// forensic `OutsideProjectRoot` signal into a silent `NotFound`. So the guard
/// sets are intentionally not unified — keep this boundary, do not add fences.
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
mod tests;
