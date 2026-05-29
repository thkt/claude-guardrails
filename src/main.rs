mod analysis;
mod config;
mod content;
mod download;
mod hook;
mod hook_exit;
mod import_map;
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
/// `DoS` / OOM guard). See ADR-0004 resource boundary axis (fail-closed exit 64).
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

Exit codes (hook mode):
  0   Pass — no violations
  1   Warning only — non-blocking severity violations, tool proceeds, stderr shown to AI
  2   Blocked — violations at or above severity.blockThreshold (default: high), tool halted
  64  Hook input error — invalid JSON, oversized payload, or clap usage failure
  70  Internal error — panic / invariant violation, fail-closed

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

fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        eprintln!("guardrails: internal error: {info}");
        process::exit(i32::from(HookExitCode::Internal.code()));
    }));
}

fn main() {
    install_panic_hook();

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

    let exit_code = match cli.command {
        Some(Commands::Prefetch) => run_prefetch(cli.json),
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
}
