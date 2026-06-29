mod analysis;
mod config;
mod content;
mod download;
mod hook;
mod hook_exit;
mod import_map;
mod invariant;
mod io;
mod regex_compile;
mod resolve;
mod rules;
mod temp_file;

use crate::io::envelope::SuccessEnvelope;
use crate::io::output::{build_payload, print_json_line, render_error};
use clap::{Parser, Subcommand};
use hook::run_hook;
use hook_exit::HookExitCode;
use serde::Serialize;
use std::panic;
use std::process;

/// 10 MB upper bound for stdin and on-disk reads (Claude Code hook stdin cap +
/// `DoS` / OOM guard). See ADR-0004 resource boundary axis (fail-closed: stdin
/// oversized blocks via exit 2).
pub(crate) const MAX_INPUT_SIZE: u64 = 10_000_000;
const SYSEXIT_USAGE: i32 = 64;

#[derive(Parser)]
#[command(
    name = "guardrails",
    version,
    about = "Pre-write guardrails for Claude Code (PreToolUse hook)",
    after_help = "\
Hook mode (no subcommand): reads tool input JSON from stdin and emits violations.
With --json: emits a structured JSON report on stdout, human-readable on stderr.

Exit codes (hook mode). Per the PreToolUse contract only exit 2 blocks the tool
call; 0 allows and 1/64/70 are non-blocking (stderr shown to AI, tool proceeds):
  0   Pass — no violations
  1   Warning only — non-blocking severity violations, tool proceeds, stderr shown to AI
  2   Blocked — violations at or above severity.blockThreshold (default: high), oversized stdin, or an internal panic mid-check (all fail-closed), tool halted
  64  Hook input error — invalid JSON, stdin read failure, or clap usage failure (non-blocking)

Exit codes (prefetch subcommand):
  0   Success
  64  Usage error
  65  Data error (unsupported platform)
  74  I/O error (download / extract / cache failure)"
)]
struct Cli {
    /// Emit a structured JSON envelope on stdout (hook violations or prefetch result).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Download oxlint binary into the cache (no-op if already present).
    Prefetch,
    /// Internal (#314): parse stdin AST-request in an isolated child so a
    /// deep-nesting stack overflow aborts this process, not the hook. Hidden:
    /// only the hook spawns it.
    #[command(name = "__ast-child", hide = true)]
    AstChild,
}

#[derive(Serialize)]
struct PrefetchSuccess {
    path: String,
}

fn run_prefetch(json_mode: bool) -> i32 {
    match download::ensure_oxlint() {
        Ok(path) => {
            let path_str = path.display().to_string();
            eprintln!("guardrails: oxlint ready at {path_str}");
            if json_mode {
                print_json_line(&SuccessEnvelope::ok(PrefetchSuccess { path: path_str }));
            }
            0
        }
        Err(e) => {
            let (code, next_step) = e.classify();
            render_error(
                json_mode,
                build_payload(code, format!("prefetch failed: {e}"), next_step),
            );
            i32::from(code.exit_code())
        }
    }
}

fn install_panic_hook(exit: HookExitCode) {
    let code = i32::from(exit.code());
    panic::set_hook(Box::new(move |info| {
        eprintln!("guardrails: internal error: {info}");
        process::exit(code);
    }));
}

/// Exit code a panic should carry, by subcommand. Hook mode (`None`) fails
/// closed (`Blocking`, exit 2): a panic mid-check means the security pass did
/// not complete, and only exit 2 blocks the `PreToolUse` call, so any other
/// code would let the unchecked edit through. The AST child keeps `Internal`
/// (its abort already maps to a parent-side block in `spawn_ast_child`), and
/// prefetch keeps `Internal` (sysexits scheme, not a hook). #379 — ADR-0004
/// invariant axis.
fn panic_exit_code(command: Option<&Commands>) -> HookExitCode {
    match command {
        None => HookExitCode::Blocking,
        Some(_) => HookExitCode::Internal,
    }
}

fn main() {
    // Cover CLI-parse and prefetch/ast-child panics with the internal-error
    // code; hook mode upgrades to Blocking once the subcommand is known.
    install_panic_hook(HookExitCode::Internal);

    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            let _ = e.print();
            let code = match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => SYSEXIT_USAGE,
            };
            process::exit(code);
        }
    };

    install_panic_hook(panic_exit_code(cli.command.as_ref()));

    let exit_code = match cli.command {
        Some(Commands::Prefetch) => run_prefetch(cli.json),
        Some(Commands::AstChild) => analysis::ast_rules::run_child(),
        None => run_hook(cli.json),
    };
    process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::envelope::ErrorCode;

    #[test]
    fn classify_unsupported_platform_maps_to_data_error() {
        let e = download::OxlintError::UnsupportedPlatform {
            os: "solaris",
            arch: "sparc",
        };
        let (code, next_step) = e.classify();
        assert_eq!(code, ErrorCode::DataError);
        assert!(
            next_step.contains("npm"),
            "next_step should suggest npm fallback: {next_step}"
        );
    }

    #[test]
    fn classify_network_failure_maps_to_io_error() {
        let e = download::OxlintError::NetworkFailure(String::from("dns lookup failed"));
        let (code, _) = e.classify();
        assert_eq!(code, ErrorCode::IoError);
    }

    #[test]
    fn classify_extract_failure_maps_to_io_error() {
        let e = download::OxlintError::ExtractFailure(String::from("disk full"));
        let (code, _) = e.classify();
        assert_eq!(code, ErrorCode::IoError);
    }

    #[test]
    fn classify_cache_dir_unavailable_maps_to_io_error() {
        let e = download::OxlintError::CacheDirUnavailable;
        let (code, _) = e.classify();
        assert_eq!(code, ErrorCode::IoError);
    }

    #[test]
    fn hook_mode_panic_fails_closed_with_blocking_exit() {
        // #379: a panic mid-check in hook mode must carry exit 2 so the
        // PreToolUse call is blocked; exit 70 was non-blocking and let the
        // unchecked edit through.
        assert_eq!(panic_exit_code(None), HookExitCode::Blocking);
    }

    #[test]
    fn subcommand_panic_keeps_internal_exit() {
        // Prefetch (sysexits) and the ast-child (abort already blocks via the
        // parent) keep the internal-error code.
        assert_eq!(
            panic_exit_code(Some(&Commands::Prefetch)),
            HookExitCode::Internal
        );
        assert_eq!(
            panic_exit_code(Some(&Commands::AstChild)),
            HookExitCode::Internal
        );
    }
}
