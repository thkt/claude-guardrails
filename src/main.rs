mod ast;
mod ast_security;
mod color;
mod config;
mod download;
mod envelope;
mod hook_exit;
mod import_map;
mod oxlint;
mod parse_json;
mod regex_util;
mod reporter;
mod resolve;
mod rules;
mod scanner;
mod tempfile_util;

use clap::{Parser, Subcommand};
use config::{Config, ConfigSource, TOOLS_CONFIG_FILE};
use envelope::{ErrorCode, ErrorEnvelope, ErrorPayload, SuccessEnvelope};
use hook_exit::HookExitCode;
use reporter::{build_json_report, format_violations, format_warnings};
use rules::{non_comment_lines, Violation, RE_JS_FILE};
use serde::Serialize;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::panic;
use std::path::{Path, PathBuf};
use std::process;

/// 10 MB upper bound for stdin and on-disk reads (Claude Code hook stdin cap +
/// `DoS` / OOM guard). See ADR-0004 resource boundary axis (fail-closed exit 64).
const MAX_INPUT_SIZE: u64 = 10_000_000;
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
  2   Blocked — violations matching severity.blockOn (default: critical, high), tool halted
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

mod tool_name {
    pub const WRITE: &str = "Write";
    pub const EDIT: &str = "Edit";
    pub const MULTI_EDIT: &str = "MultiEdit";
}

#[derive(serde::Deserialize)]
struct ToolInput {
    tool_name: String,
    tool_input: ToolInputData,
}

#[derive(serde::Deserialize, Default)]
struct ToolInputData {
    file_path: Option<String>,
    content: Option<String>,
    new_string: Option<String>,
    old_string: Option<String>,
    #[serde(default)]
    replace_all: bool,
    edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize, Default)]
struct EditItem {
    new_string: Option<String>,
    old_string: Option<String>,
    #[serde(default)]
    replace_all: bool,
}

/// Reason analysis fell back to the Edit/MultiEdit snippet instead of
/// post-edit full file content. Distinct from `NotApplicable` (intentional
/// snippet mode, e.g., non-JS file) — every variant here means the caller
/// wanted full context but could not get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DegradedReason {
    OversizedFile,
    NonUtf8Content,
    FileNotFound,
    PermissionDenied,
    IoError,
    OldStringNotFound,
    MultiEditMidFailure(usize),
    PathOutsideProject,
}

impl DegradedReason {
    fn note(self) -> String {
        match self {
            Self::OversizedFile => format!(
                "Target file exceeds {MAX_INPUT_SIZE}-byte limit; analyzed Edit snippet only."
            ),
            Self::NonUtf8Content => {
                "Target file is not valid UTF-8; analyzed Edit snippet only.".to_owned()
            }
            Self::FileNotFound => "Target file not on disk; analyzed Edit snippet only.".to_owned(),
            Self::PermissionDenied => {
                "Permission denied reading target file; analyzed Edit snippet only.".to_owned()
            }
            Self::IoError => {
                "I/O error reading target file; analyzed Edit snippet only.".to_owned()
            }
            Self::OldStringNotFound => {
                "Edit pattern not found in target file; analyzed Edit snippet only.".to_owned()
            }
            Self::MultiEditMidFailure(idx) => format!(
                "MultiEdit edit {idx} did not match post-edit content; analyzed Edit snippet only."
            ),
            Self::PathOutsideProject => {
                "Target file resolves outside the project root (symlink or path traversal); analyzed Edit snippet only.".to_owned()
            }
        }
    }
}

/// Result of resolving full post-edit content for a hook invocation.
/// - `Full`: full file content reconstructed (post-write semantic intact).
/// - `Degraded`: caller wanted full context, failed for a documented reason.
/// - `NotApplicable`: full-file analysis not attempted (non-JS file, missing
///   `old_string`, etc.). Silent fallback to snippet is correct here.
enum ContentResolution {
    Full(String),
    Degraded(DegradedReason),
    NotApplicable,
}

struct ResolvedTarget {
    file_path: String,
    content: String,
    is_js: bool,
    degraded: Option<DegradedReason>,
}

fn get_file_and_content(input: &ToolInput, project_root: Option<&Path>) -> Option<ResolvedTarget> {
    let file_path = input.tool_input.file_path.clone()?;
    let is_js = RE_JS_FILE.is_match(&file_path);

    let (content, degraded) = match input.tool_name.as_str() {
        tool_name::WRITE => (input.tool_input.content.clone()?, None),
        tool_name::EDIT => {
            let new_string = input.tool_input.new_string.clone()?;
            match resolve_edit_content(
                &file_path,
                input.tool_input.old_string.as_deref(),
                &new_string,
                input.tool_input.replace_all,
                project_root,
                is_js,
            ) {
                ContentResolution::Full(c) => (c, None),
                ContentResolution::Degraded(reason) => (new_string, Some(reason)),
                ContentResolution::NotApplicable => (new_string, None),
            }
        }
        tool_name::MULTI_EDIT => {
            let edits = input.tool_input.edits.as_ref()?;
            match resolve_multi_edit_content(&file_path, edits, project_root, is_js) {
                ContentResolution::Full(c) => (c, None),
                ContentResolution::Degraded(reason) => (join_new_strings(edits), Some(reason)),
                ContentResolution::NotApplicable => (join_new_strings(edits), None),
            }
        }
        _ => {
            if input.tool_input.content.is_some() || input.tool_input.new_string.is_some() {
                eprintln!(
                    "guardrails: unknown tool '{}' has content fields — add to get_file_and_content if it writes files",
                    input.tool_name
                );
            }
            return None;
        }
    };

    if file_path.is_empty() || content.is_empty() {
        return None;
    }

    Some(ResolvedTarget {
        file_path,
        content,
        is_js,
        degraded,
    })
}

fn join_new_strings(edits: &[EditItem]) -> String {
    edits
        .iter()
        .filter_map(|e| e.new_string.as_deref())
        .collect::<Vec<_>>()
        .join("\n")
}

fn apply_edit(
    file_content: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> Option<String> {
    if old_string.is_empty() {
        return None;
    }
    if replace_all {
        let mut matched = false;
        let mut result = String::with_capacity(file_content.len());
        let mut cursor = 0;
        for (idx, _) in file_content.match_indices(old_string) {
            matched = true;
            result.push_str(&file_content[cursor..idx]);
            result.push_str(new_string);
            cursor = idx + old_string.len();
        }
        if !matched {
            return None;
        }
        result.push_str(&file_content[cursor..]);
        Some(result)
    } else {
        let idx = file_content.find(old_string)?;
        let mut result =
            String::with_capacity(file_content.len() + new_string.len() - old_string.len());
        result.push_str(&file_content[..idx]);
        result.push_str(new_string);
        result.push_str(&file_content[idx + old_string.len()..]);
        Some(result)
    }
}

/// Bound on-disk file read at `MAX_INPUT_SIZE` to mirror the stdin cap.
/// Canonicalizes the path; when `project_root` is `Some`, rejects targets
/// resolving outside that root (defense against symlink / `..` path
/// traversal). Production callers pass canonical cwd; `None` disables the
/// boundary (used by tests over tempdirs).
///
/// `is_js` is taken as input to avoid re-running `RE_JS_FILE.is_match` on
/// an already-classified path. Pass `RE_JS_FILE.is_match(file_path)` when
/// no classification has been done yet.
fn read_file_capped(
    file_path: &str,
    project_root: Option<&Path>,
    is_js: bool,
) -> ContentResolution {
    if !is_js {
        return ContentResolution::NotApplicable;
    }
    let canonical = match fs::canonicalize(file_path) {
        Ok(p) => p,
        Err(e) => return ContentResolution::Degraded(io_error_to_reason(&e)),
    };
    if let Some(root) = project_root {
        if !canonical.starts_with(root) {
            return ContentResolution::Degraded(DegradedReason::PathOutsideProject);
        }
    }
    let file = match fs::File::open(&canonical) {
        Ok(f) => f,
        Err(e) => return ContentResolution::Degraded(io_error_to_reason(&e)),
    };
    let mut buf = String::new();
    if let Err(e) = file.take(MAX_INPUT_SIZE + 1).read_to_string(&mut buf) {
        return ContentResolution::Degraded(io_error_to_reason(&e));
    }
    if !content_within_cap(&buf, MAX_INPUT_SIZE) {
        return ContentResolution::Degraded(DegradedReason::OversizedFile);
    }
    ContentResolution::Full(buf)
}

/// Pure size-cap predicate. Cap is parameterized so the boundary is
/// testable with small fixtures (no 10MB allocation required).
fn content_within_cap(content: &str, cap: u64) -> bool {
    u64::try_from(content.len()).is_ok_and(|n| n <= cap)
}

fn io_error_to_reason(e: &io::Error) -> DegradedReason {
    match e.kind() {
        io::ErrorKind::NotFound => DegradedReason::FileNotFound,
        io::ErrorKind::PermissionDenied => DegradedReason::PermissionDenied,
        io::ErrorKind::InvalidData => DegradedReason::NonUtf8Content,
        _ => DegradedReason::IoError,
    }
}

fn resolve_edit_content(
    file_path: &str,
    old_string: Option<&str>,
    new_string: &str,
    replace_all: bool,
    project_root: Option<&Path>,
    is_js: bool,
) -> ContentResolution {
    let Some(old) = old_string else {
        return ContentResolution::NotApplicable;
    };
    let content = match read_file_capped(file_path, project_root, is_js) {
        ContentResolution::Full(c) => c,
        other => return other,
    };
    match apply_edit(&content, old, new_string, replace_all) {
        Some(applied) => ContentResolution::Full(applied),
        None => ContentResolution::Degraded(DegradedReason::OldStringNotFound),
    }
}

fn resolve_multi_edit_content(
    file_path: &str,
    edits: &[EditItem],
    project_root: Option<&Path>,
    is_js: bool,
) -> ContentResolution {
    let mut current = match read_file_capped(file_path, project_root, is_js) {
        ContentResolution::Full(c) => c,
        other => return other,
    };
    for (idx, edit) in edits.iter().enumerate() {
        let Some(old) = edit.old_string.as_deref() else {
            return ContentResolution::NotApplicable;
        };
        let Some(new) = edit.new_string.as_deref() else {
            return ContentResolution::NotApplicable;
        };
        match apply_edit(&current, old, new, edit.replace_all) {
            Some(applied) => current = applied,
            None => return ContentResolution::Degraded(DegradedReason::MultiEditMidFailure(idx)),
        }
    }
    ContentResolution::Full(current)
}

fn lint_with_external_tools(
    content: &str,
    file_path: &str,
    config: &Config,
    project_root: Option<&Path>,
) -> (Vec<Violation>, Vec<String>) {
    if !config.rules.oxlint {
        return (Vec::new(), Vec::new());
    }

    // `resolve_notes` carries the `OutsideProjectRoot` reject record (if any)
    // independently from the bundled-fallback outcome. Both must surface in
    // the envelope so an attack-detection signal is not collapsed into a
    // generic "oxlint not available" note.
    let (bin, mut notes) = oxlint::resolve(file_path, project_root);
    let Some(bin) = bin else {
        if env::var_os("GUARDRAILS_VERBOSE").is_some() {
            eprintln!("guardrails: warning: oxlint not available for {file_path}");
        }
        notes.push(String::from("oxlint not found, JS lint skipped"));
        return (Vec::new(), notes);
    };

    let Some(violations) = oxlint::check(content, file_path, &bin, &config.oxlint_config) else {
        notes.push(String::from("oxlint check failed, JS lint skipped"));
        return (Vec::new(), notes);
    };
    (violations, notes)
}

fn lint_with_ast(
    content: &str,
    file_path: &str,
    config: &Config,
) -> (Vec<Violation>, Option<String>) {
    // Skip the parse when every AST-driven rule is disabled. The flag list
    // here must stay in lockstep with the per-rule dispatch arms below; a
    // missing rule on either side reintroduces the drift that motivated
    // removing the outer `has_ast_rules` guard.
    if !config.rules.ast_security
        && !config.rules.no_use_effect
        && !config.rules.open_redirect
        && !config.rules.eval
        && !config.rules.sqli_concat
        && !config.rules.cors_wildcard
    {
        return (Vec::new(), None);
    }
    let result = ast::with_parsed_program(content, file_path, |program, line_offsets| {
        let mut found = Vec::new();
        if config.rules.ast_security {
            if let Some(v) = ast_security::check_bidi(content, file_path, line_offsets) {
                found.push(v);
            }
            found.extend(ast_security::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if config.rules.no_use_effect {
            found.extend(rules::no_use_effect::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if config.rules.open_redirect {
            found.extend(rules::open_redirect::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if config.rules.eval {
            let import_map = import_map::ImportMap::build(program);
            found.extend(rules::eval::check_program(
                program,
                line_offsets,
                file_path,
                &import_map,
            ));
        }
        if config.rules.sqli_concat {
            found.extend(rules::sqli_concat::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if config.rules.cors_wildcard {
            found.extend(rules::cors_wildcard::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        found
    });
    match result {
        Some(v) => (v, None),
        None => (
            Vec::new(),
            Some(String::from("AST parse failed, structural rules skipped")),
        ),
    }
}

fn collect_violations(
    file_path: &str,
    content: &str,
    config: &Config,
    project_root: Option<&Path>,
    is_js: bool,
) -> (Vec<Violation>, Vec<String>) {
    let mut violations = Vec::new();
    let mut notes = Vec::new();

    if is_js {
        let (vs, ns) = lint_with_external_tools(content, file_path, config, project_root);
        violations.extend(vs);
        notes.extend(ns);
    }

    let lines = non_comment_lines(content);
    let rules = rules::load_rules(config);
    for rule in &rules {
        if !rule.file_pattern.is_match(file_path) {
            continue;
        }
        violations.extend(rule.check(content, file_path, &lines));
    }

    if is_js {
        let (vs, note) = lint_with_ast(content, file_path, config);
        violations.extend(vs);
        if let Some(n) = note {
            notes.push(n);
        }
    }

    (violations, notes)
}

fn partition_violations<'a>(
    violations: &'a [Violation],
    config: &Config,
) -> (Vec<&'a Violation>, Vec<&'a Violation>) {
    violations
        .iter()
        .partition(|v| config.severity.block_on.contains(&v.severity))
}

fn build_payload(code: ErrorCode, message: String, next_step: &str) -> ErrorPayload {
    ErrorPayload {
        code,
        message,
        next_step: Some(String::from(next_step)),
        candidates: vec![],
        retryable: false,
    }
}

// Side-effecting error render: a stderr line plus the JSON envelope when
// enabled. Exit code is the caller's responsibility (hook input errors map to
// 64 per ADR-0005; prefetch errors use `ErrorCode::exit_code`).
fn render_error(json_mode: bool, payload: ErrorPayload) {
    eprintln!("guardrails: {}", payload.message);
    emit_error_envelope_if_enabled(json_mode, payload);
}

// Fail-closed input parsing. Errors carry the cause as a typed variant; the
// exit code (always 64, hook input contract per ADR-0005) and rendering are
// the caller's responsibility.
#[derive(Debug, thiserror::Error)]
enum ParseStdinError {
    #[error("failed to read stdin: {0}")]
    Io(#[from] io::Error),
    #[error("input too large (>{cap} bytes), blocking as precaution")]
    Oversized { cap: u64 },
    #[error("invalid JSON input: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

impl ParseStdinError {
    fn into_payload(self) -> ErrorPayload {
        let (code, next_step) = match &self {
            Self::Io(_) => (
                ErrorCode::IoError,
                "Pass valid Claude Code hook JSON via stdin",
            ),
            Self::Oversized { .. } => (
                ErrorCode::DataError,
                "Reduce input size or split into smaller hook calls",
            ),
            Self::InvalidJson(_) => (
                ErrorCode::DataError,
                "Pass valid Claude Code hook JSON with tool_name and tool_input fields",
            ),
        };
        build_payload(code, self.to_string(), next_step)
    }
}

fn parse_stdin() -> Result<ToolInput, ParseStdinError> {
    parse_stdin_from(&mut io::stdin().lock())
}

fn parse_stdin_from(reader: &mut dyn Read) -> Result<ToolInput, ParseStdinError> {
    let mut input_str = String::new();
    reader
        .take(MAX_INPUT_SIZE + 1)
        .read_to_string(&mut input_str)?;

    if !content_within_cap(&input_str, MAX_INPUT_SIZE) {
        return Err(ParseStdinError::Oversized {
            cap: MAX_INPUT_SIZE,
        });
    }

    Ok(serde_json::from_str(&input_str)?)
}

const CONFIG_HINT_MESSAGE: &str =
    "Guardrails: using defaults. Customize via .guardrails.json \u{2014} see https://github.com/thkt/guardrails#configuration";

#[derive(Debug, PartialEq)]
enum HintAction {
    Skip,
    Hint,
}

fn config_hint_action(git_root: &Path, config: &Config) -> HintAction {
    if config.source != ConfigSource::Default {
        return HintAction::Skip;
    }
    let tools_path = git_root.join(TOOLS_CONFIG_FILE);
    if tools_path.exists() || tools_path.parent().is_some_and(Path::is_dir) {
        HintAction::Hint
    } else {
        HintAction::Skip
    }
}

fn show_config_hint(config: &Config) {
    let Some(ref git_root) = config.git_root else {
        return;
    };
    match config_hint_action(git_root, config) {
        HintAction::Skip => {}
        HintAction::Hint => {
            eprintln!("{}", color::yellow(CONFIG_HINT_MESSAGE));
        }
    }
}

fn emit_human_violations(blocking: &[&Violation], warnings: &[&Violation]) {
    if !warnings.is_empty() {
        eprintln!("{}", format_warnings(warnings));
    }
    if !blocking.is_empty() {
        eprintln!("{}", format_violations(blocking));
    }
}

fn print_json_line<T: Serialize>(value: &T) {
    let json = serde_json::to_string(value)
        .expect("print_json_line: envelope serialization is infallible");
    // Ignore write errors (e.g. BrokenPipe) so the caller's exit code is preserved.
    let _ = writeln!(io::stdout().lock(), "{json}");
}

fn emit_json_if_enabled(
    json_mode: bool,
    blocking: &[&Violation],
    warnings: &[&Violation],
    notes: Vec<String>,
) {
    if !json_mode {
        return;
    }
    let report = build_json_report(blocking, warnings);
    print_json_line(&SuccessEnvelope::with_notes(report, notes));
}

fn emit_error_envelope_if_enabled(json_mode: bool, payload: ErrorPayload) {
    if !json_mode {
        return;
    }
    print_json_line(&ErrorEnvelope { error: payload });
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

fn resolve_project_root_or_note(
    result: io::Result<PathBuf>,
    notes: &mut Vec<String>,
) -> Option<PathBuf> {
    match result {
        Ok(p) => Some(p),
        Err(e) => {
            let note = format!(
                "cannot resolve project root ({e}); path-traversal boundary check disabled"
            );
            eprintln!("guardrails: warning: {note}");
            notes.push(note);
            None
        }
    }
}

fn load_config_or_note(result: Result<Config, String>, notes: &mut Vec<String>) -> Config {
    match result {
        Ok(c) => c,
        Err(e) => {
            let note = format!(
                "config error (using defaults: all rules enabled, block_on=[critical,high]): {e}"
            );
            eprintln!("guardrails: {note}");
            notes.push(note);
            Config::default()
        }
    }
}

fn run_hook(json_mode: bool) -> i32 {
    let input = match parse_stdin() {
        Ok(v) => v,
        Err(e) => {
            render_error(json_mode, e.into_payload());
            return i32::from(HookExitCode::InputError.code());
        }
    };
    run_hook_with_input(
        &input,
        env::current_dir().and_then(fs::canonicalize),
        || Config::default().with_project_overrides(),
        json_mode,
    )
}

/// Runs the hook against a parsed `ToolInput`, returning a sysexits exit code.
///
/// `load_config` is `FnOnce` so config is **deferred** past the unsupported-tool
/// / empty-content early-returns: those paths never read `.claude/tools.json`,
/// keeping hook startup off the disk for tool calls we do not audit. The same
/// seam lets tests inject a stub config without touching the real loader.
fn run_hook_with_input<F>(
    input: &ToolInput,
    project_root_result: io::Result<PathBuf>,
    load_config: F,
    json_mode: bool,
) -> i32
where
    F: FnOnce() -> Result<Config, String>,
{
    let mut notes = Vec::new();
    let project_root = resolve_project_root_or_note(project_root_result, &mut notes);

    let Some(ResolvedTarget {
        file_path,
        content,
        is_js,
        degraded,
    }) = get_file_and_content(input, project_root.as_deref())
    else {
        let is_write_tool = matches!(
            input.tool_name.as_str(),
            tool_name::WRITE | tool_name::EDIT | tool_name::MULTI_EDIT
        );
        if is_write_tool {
            eprintln!(
                "guardrails: warning: {} has missing or empty file_path/content",
                input.tool_name
            );
        } else {
            eprintln!(
                "guardrails: skipping {} (unsupported tool)",
                input.tool_name
            );
        }
        emit_json_if_enabled(json_mode, &[], &[], notes);
        return 0;
    };

    let config = load_config_or_note(load_config(), &mut notes);

    show_config_hint(&config);

    if !config.enabled {
        emit_json_if_enabled(json_mode, &[], &[], notes);
        return 0;
    }

    let (violations, lint_notes) = collect_violations(
        &file_path,
        &content,
        &config,
        project_root.as_deref(),
        is_js,
    );
    notes.extend(lint_notes);
    if let Some(reason) = degraded {
        let note = reason.note();
        eprintln!("guardrails: degraded: {note}");
        notes.push(note);
    }
    let (blocking, warnings) = partition_violations(&violations, &config);

    emit_json_if_enabled(json_mode, &blocking, &warnings, notes);
    emit_human_violations(&blocking, &warnings);
    let outcome = if !blocking.is_empty() {
        HookExitCode::Blocking
    } else if !warnings.is_empty() {
        HookExitCode::Advisory
    } else {
        HookExitCode::Pass
    };
    i32::from(outcome.code())
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
    use rules::Severity;

    fn make_write_input(file_path: Option<&str>, content: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name::WRITE.to_owned(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                content: content.map(String::from),
                ..ToolInputData::default()
            },
        }
    }

    fn make_edit_input(file_path: Option<&str>, new_string: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name::EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                new_string: new_string.map(String::from),
                ..ToolInputData::default()
            },
        }
    }

    fn make_violation(rule: &str, severity: Severity) -> Violation {
        Violation {
            rule: rule.to_owned(),
            severity,
            fix: "fix".to_owned(),
            file: "/test.ts".to_owned(),
            line: Some(1),
        }
    }

    fn temp_ts_file(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn write_extracts_content() {
        let input = make_write_input(Some("/src/app.ts"), Some("const x = 1;"));
        let ResolvedTarget {
            file_path: path,
            content,
            ..
        } = get_file_and_content(&input, None).unwrap();
        assert_eq!(path, "/src/app.ts");
        assert_eq!(content, "const x = 1;");
    }

    #[test]
    fn edit_extracts_new_string() {
        let input = make_edit_input(Some("/src/app.ts"), Some("const y = 2;"));
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "const y = 2;");
    }

    #[test]
    fn multi_edit_joins_edits() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_owned()),
                edits: Some(vec![
                    EditItem {
                        new_string: Some("line1".to_owned()),
                        ..EditItem::default()
                    },
                    EditItem {
                        new_string: Some("line2".to_owned()),
                        ..EditItem::default()
                    },
                ]),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "line1\nline2");
    }

    #[test]
    fn multi_edit_join_preserves_separator_before_empty_string() {
        // Regression: the fold-based join silently dropped the leading
        // separator when the first edit's new_string was empty, shifting
        // line offsets in downstream snippet analysis.
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/nonexistent/path.ts".to_owned()),
                edits: Some(vec![
                    EditItem {
                        old_string: Some("foo".to_owned()),
                        new_string: Some(String::new()),
                        ..EditItem::default()
                    },
                    EditItem {
                        old_string: Some("bar".to_owned()),
                        new_string: Some("kept".to_owned()),
                        ..EditItem::default()
                    },
                ]),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "\nkept");
    }

    #[test]
    fn multi_edit_empty_edits_returns_none() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_owned()),
                edits: Some(vec![]),
                ..ToolInputData::default()
            },
        };
        assert!(get_file_and_content(&input, None).is_none());
    }

    #[test]
    fn multi_edit_all_none_returns_none() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_owned()),
                edits: Some(vec![EditItem::default(), EditItem::default()]),
                ..ToolInputData::default()
            },
        };
        assert!(get_file_and_content(&input, None).is_none());
    }

    #[test]
    fn unsupported_tool_returns_none() {
        let input = ToolInput {
            tool_name: "Bash".to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/tmp/x".to_owned()),
                content: Some("echo hi".to_owned()),
                ..ToolInputData::default()
            },
        };
        assert!(get_file_and_content(&input, None).is_none());
    }

    #[test]
    fn invalid_path_or_content_returns_none() {
        for (label, path, content) in [
            ("empty path", Some(""), Some("content")),
            ("empty content", Some("/src/app.ts"), Some("")),
            ("missing path", None, Some("content")),
        ] {
            let input = make_write_input(path, content);
            assert!(
                get_file_and_content(&input, None).is_none(),
                "case: {label}"
            );
        }
    }

    #[test]
    fn apply_edit_replaces_first_occurrence() {
        let got = apply_edit("foo bar foo", "foo", "X", false).unwrap();
        assert_eq!(got, "X bar foo");
    }

    #[test]
    fn apply_edit_replace_all_replaces_every_occurrence() {
        let got = apply_edit("foo bar foo", "foo", "X", true).unwrap();
        assert_eq!(got, "X bar X");
    }

    #[test]
    fn apply_edit_returns_none_when_old_string_not_found() {
        assert!(apply_edit("foo", "bar", "X", false).is_none());
        assert!(apply_edit("foo", "bar", "X", true).is_none());
    }

    #[test]
    fn apply_edit_returns_none_when_old_string_empty() {
        assert!(apply_edit("foo", "", "X", false).is_none());
        assert!(apply_edit("foo", "", "X", true).is_none());
    }

    // TC-001: self-referential new_string. Rust `str::replace` does NOT
    // re-scan already-replaced output, so a `new_string` containing the
    // `old_string` does not cascade. Documenting this invariant.
    #[test]
    fn apply_edit_self_referential_new_string_does_not_cascade() {
        let got = apply_edit("a a", "a", "aa", false).unwrap();
        assert_eq!(got, "aa a", "replacen replaces only first occurrence");
        let got_all = apply_edit("a a", "a", "aa", true).unwrap();
        assert_eq!(got_all, "aa aa", "replace does not re-scan output");
    }

    // TC-008: empty `new_string` is a valid deletion operation.
    #[test]
    fn apply_edit_deletion_with_empty_new_string() {
        let got = apply_edit("foo bar", "foo ", "", false).unwrap();
        assert_eq!(
            got, "bar",
            "deletes old_string including trailing whitespace"
        );
        let got_all = apply_edit("a-x-b-x-c", "x", "", true).unwrap();
        assert_eq!(got_all, "a--b--c", "replace_all deletes every occurrence");
    }

    #[test]
    fn edit_reads_full_file_and_applies_substitution() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("file.ts");
        fs::write(
            &path,
            "import { exec } from 'child_process';\nconst x = 1;\n",
        )
        .unwrap();
        let input = ToolInput {
            tool_name: tool_name::EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some(path.to_string_lossy().into_owned()),
                old_string: Some("const x = 1;".to_owned()),
                new_string: Some("const y = 2;".to_owned()),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(
            content,
            "import { exec } from 'child_process';\nconst y = 2;\n"
        );
    }

    #[test]
    fn edit_falls_back_to_snippet_when_file_missing() {
        let input = ToolInput {
            tool_name: tool_name::EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/nonexistent/path/that/does/not/exist.ts".to_owned()),
                old_string: Some("const x = 1;".to_owned()),
                new_string: Some("eval(userInput);".to_owned()),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "eval(userInput);");
    }

    #[test]
    fn edit_falls_back_to_snippet_when_old_string_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("file.ts");
        fs::write(&path, "const a = 1;\n").unwrap();
        let input = ToolInput {
            tool_name: tool_name::EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some(path.to_string_lossy().into_owned()),
                old_string: Some("not in file".to_owned()),
                new_string: Some("eval(userInput);".to_owned()),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "eval(userInput);");
    }

    #[test]
    fn multi_edit_applies_sequentially_to_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("file.ts");
        fs::write(&path, "let a = 1;\nlet b = 2;\n").unwrap();
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some(path.to_string_lossy().into_owned()),
                edits: Some(vec![
                    EditItem {
                        old_string: Some("let a = 1;".to_owned()),
                        new_string: Some("let a = 10;".to_owned()),
                        ..EditItem::default()
                    },
                    EditItem {
                        old_string: Some("let b = 2;".to_owned()),
                        new_string: Some("let b = 20;".to_owned()),
                        ..EditItem::default()
                    },
                ]),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "let a = 10;\nlet b = 20;\n");
    }

    #[test]
    fn multi_edit_falls_back_when_file_missing() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/nonexistent/path.ts".to_owned()),
                edits: Some(vec![EditItem {
                    new_string: Some("eval(userInput);".to_owned()),
                    old_string: Some("none".to_owned()),
                    ..EditItem::default()
                }]),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "eval(userInput);");
    }

    #[test]
    fn read_file_capped_returns_full_for_valid_js() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&tmp, "ok.ts", "const x = 1;\n");
        match read_file_capped(path.to_str().unwrap(), None, true) {
            ContentResolution::Full(c) => assert_eq!(c, "const x = 1;\n"),
            _ => panic!("expected Full"),
        }
    }

    #[test]
    fn read_file_capped_returns_not_applicable_for_non_js() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&tmp, "readme.md", "hello");
        assert!(matches!(
            read_file_capped(path.to_str().unwrap(), None, false),
            ContentResolution::NotApplicable
        ));
    }

    #[test]
    fn read_file_capped_degrades_on_file_not_found() {
        assert!(matches!(
            read_file_capped("/nonexistent/path/that/does/not/exist.ts", None, true),
            ContentResolution::Degraded(DegradedReason::FileNotFound)
        ));
    }

    #[test]
    fn read_file_capped_degrades_on_non_utf8() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("binary.ts");
        fs::write(&path, [0xff, 0xfe, 0xfd, 0xfc]).unwrap();
        assert!(matches!(
            read_file_capped(path.to_str().unwrap(), None, true),
            ContentResolution::Degraded(DegradedReason::NonUtf8Content)
        ));
    }

    #[test]
    fn content_within_cap_accepts_empty() {
        assert!(content_within_cap("", 100));
    }

    #[test]
    fn content_within_cap_accepts_one_byte_under_cap() {
        assert!(content_within_cap(&"a".repeat(99), 100));
    }

    #[test]
    fn content_within_cap_accepts_at_exact_cap() {
        assert!(content_within_cap(&"a".repeat(100), 100));
    }

    #[test]
    fn content_within_cap_rejects_one_byte_over_cap() {
        assert!(!content_within_cap(&"a".repeat(101), 100));
    }

    #[test]
    fn content_within_cap_accepts_zero_cap_only_for_empty() {
        assert!(content_within_cap("", 0));
        assert!(!content_within_cap("a", 0));
    }

    #[test]
    fn read_file_capped_degrades_on_oversized_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("huge.ts");
        let size = usize::try_from(MAX_INPUT_SIZE + 1).unwrap();
        fs::write(&path, "a".repeat(size)).unwrap();
        assert!(matches!(
            read_file_capped(path.to_str().unwrap(), None, true),
            ContentResolution::Degraded(DegradedReason::OversizedFile)
        ));
    }

    #[test]
    fn read_file_capped_accepts_exactly_max_size() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("limit.ts");
        let size = usize::try_from(MAX_INPUT_SIZE).unwrap();
        fs::write(&path, "a".repeat(size)).unwrap();
        match read_file_capped(path.to_str().unwrap(), None, true) {
            ContentResolution::Full(c) => {
                assert_eq!(u64::try_from(c.len()).unwrap(), MAX_INPUT_SIZE);
            }
            _ => panic!("expected Full at exact MAX_INPUT_SIZE boundary"),
        }
    }

    #[test]
    fn read_file_capped_accepts_file_within_explicit_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let path = temp_ts_file(&tmp, "ok.ts", "const x = 1;\n");
        match read_file_capped(path.to_str().unwrap(), Some(&root), true) {
            ContentResolution::Full(c) => assert_eq!(c, "const x = 1;\n"),
            _ => panic!("expected Full when file is within explicit root"),
        }
    }

    #[test]
    fn read_file_capped_degrades_when_file_outside_explicit_root() {
        let root_tmp = tempfile::TempDir::new().unwrap();
        let root = fs::canonicalize(root_tmp.path()).unwrap();
        // file lives in a *different* tempdir, outside `root`
        let other_tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&other_tmp, "evil.ts", "const x = 1;\n");
        assert!(matches!(
            read_file_capped(path.to_str().unwrap(), Some(&root), true),
            ContentResolution::Degraded(DegradedReason::PathOutsideProject)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_file_capped_degrades_on_symlink_pointing_outside_root() {
        use std::os::unix::fs::symlink;
        let root_tmp = tempfile::TempDir::new().unwrap();
        let root = fs::canonicalize(root_tmp.path()).unwrap();
        // Real file outside the root
        let outside_tmp = tempfile::TempDir::new().unwrap();
        let outside = temp_ts_file(&outside_tmp, "secret.ts", "stolen content");
        // Symlink inside root pointing to the outside file
        let link = root_tmp.path().join("evil.ts");
        symlink(&outside, &link).unwrap();
        assert!(matches!(
            read_file_capped(link.to_str().unwrap(), Some(&root), true),
            ContentResolution::Degraded(DegradedReason::PathOutsideProject)
        ));
    }

    #[test]
    fn resolve_edit_content_degrades_on_old_string_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&tmp, "file.ts", "const a = 1;");
        let result = resolve_edit_content(
            path.to_str().unwrap(),
            Some("missing pattern"),
            "x",
            false,
            None,
            true,
        );
        assert!(matches!(
            result,
            ContentResolution::Degraded(DegradedReason::OldStringNotFound)
        ));
    }

    #[test]
    fn resolve_edit_content_not_applicable_without_old_string() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&tmp, "file.ts", "const a = 1;");
        let result = resolve_edit_content(path.to_str().unwrap(), None, "x", false, None, true);
        assert!(matches!(result, ContentResolution::NotApplicable));
    }

    #[test]
    fn resolve_multi_edit_content_degrades_on_mid_failure() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&tmp, "file.ts", "let a = 1;\n");
        let edits = vec![
            EditItem {
                old_string: Some("let a = 1;".to_owned()),
                new_string: Some("let a = 10;".to_owned()),
                ..EditItem::default()
            },
            EditItem {
                old_string: Some("not in file".to_owned()),
                new_string: Some("eval(x);".to_owned()),
                ..EditItem::default()
            },
        ];
        let result = resolve_multi_edit_content(path.to_str().unwrap(), &edits, None, true);
        match result {
            ContentResolution::Degraded(DegradedReason::MultiEditMidFailure(idx)) => {
                assert_eq!(idx, 1, "second edit (index 1) should be the failure point");
            }
            _ => panic!("expected MultiEditMidFailure(1)"),
        }
    }

    #[test]
    fn get_file_and_content_propagates_degraded_reason() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = temp_ts_file(&tmp, "file.ts", "const a = 1;");
        let input = ToolInput {
            tool_name: tool_name::EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some(path.to_string_lossy().into_owned()),
                old_string: Some("missing pattern".to_owned()),
                new_string: Some("eval(x);".to_owned()),
                ..ToolInputData::default()
            },
        };
        let ResolvedTarget {
            content, degraded, ..
        } = get_file_and_content(&input, None).unwrap();
        assert_eq!(content, "eval(x);");
        assert_eq!(degraded, Some(DegradedReason::OldStringNotFound));
    }

    #[test]
    fn degraded_reason_note_contains_actionable_text() {
        let note = DegradedReason::OversizedFile.note();
        assert!(note.contains("exceeds"));
        assert!(note.contains("snippet"));
        let note = DegradedReason::MultiEditMidFailure(2).note();
        assert!(note.contains("edit 2"));
    }

    #[test]
    fn collect_violations_detects_eval() {
        let config = Config::default();
        let (violations, _notes) =
            collect_violations("/src/app.ts", "eval(userInput);", &config, None, true);
        assert!(violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_clean_code() {
        let config = Config::default();
        let (violations, _notes) = collect_violations(
            "/src/app.ts",
            "export function main() {}\n",
            &config,
            None,
            true,
        );
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn collect_violations_disabled_rule_skipped() {
        let mut config = Config::default();
        config.rules.eval = false;
        let (violations, _notes) =
            collect_violations("/src/app.ts", "eval(userInput);", &config, None, true);
        assert!(!violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_non_js_skips_js_rules() {
        let config = Config::default();
        let (violations, _notes) =
            collect_violations("/README.md", "eval(userInput);", &config, None, false);
        assert!(!violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_ast_security_detects_injection() {
        let config = Config::default();
        let (violations, _notes) = collect_violations(
            "/src/app/api/users/route.ts",
            "exec(userInput);",
            &config,
            None,
            true,
        );
        assert!(violations
            .iter()
            .any(|v| v.rule == "child-process-injection"));
    }

    #[test]
    fn collect_violations_ast_security_disabled() {
        let mut config = Config::default();
        config.rules.ast_security = false;
        let (violations, _notes) = collect_violations(
            "/src/app/api/users/route.ts",
            "exec(userInput);",
            &config,
            None,
            true,
        );
        assert!(!violations
            .iter()
            .any(|v| v.rule == "child-process-injection"));
    }

    #[test]
    fn collect_violations_no_use_effect_detects_in_tsx() {
        let config = Config::default();
        let (violations, _notes) = collect_violations(
            "/src/App.tsx",
            "useEffect(() => { fetchData(); }, []);",
            &config,
            None,
            true,
        );
        assert!(violations.iter().any(|v| v.rule == "no-use-effect"));
    }

    #[test]
    fn collect_violations_no_use_effect_disabled() {
        let mut config = Config::default();
        config.rules.no_use_effect = false;
        let (violations, _notes) = collect_violations(
            "/src/App.tsx",
            "useEffect(() => { fetchData(); }, []);",
            &config,
            None,
            true,
        );
        assert!(!violations.iter().any(|v| v.rule == "no-use-effect"));
    }

    #[test]
    fn partition_default_severity_routing() {
        let config = Config::default();
        for (severity, expect_block) in [
            (Severity::Critical, true),
            (Severity::High, true),
            (Severity::Medium, false),
        ] {
            let violations = vec![make_violation("test", severity)];
            let (blocking, warnings) = partition_violations(&violations, &config);
            assert_eq!(
                !blocking.is_empty(),
                expect_block,
                "{severity:?} should {}",
                if expect_block { "block" } else { "warn" }
            );
            assert_eq!(
                !warnings.is_empty(),
                !expect_block,
                "{severity:?} should {}",
                if expect_block { "block" } else { "warn" }
            );
        }
    }

    #[test]
    fn partition_custom_block_on() {
        let mut config = Config::default();
        config.severity.block_on = vec![Severity::Medium];
        let violations = vec![
            make_violation("high-rule", Severity::High),
            make_violation("medium-rule", Severity::Medium),
        ];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].rule, "medium-rule");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].rule, "high-rule");
    }

    #[test]
    fn partition_empty_violations() {
        let config = Config::default();
        let violations: Vec<Violation> = vec![];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert!(blocking.is_empty());
        assert!(warnings.is_empty());
    }

    fn tmp_with_claude() -> tempfile::TempDir {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".claude")).unwrap();
        tmp
    }

    #[test]
    fn hint_action_skip_when_explicit_source() {
        let tmp = tmp_with_claude();
        let config = Config {
            source: ConfigSource::Explicit,
            ..Config::default()
        };
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Skip);
    }

    #[test]
    fn hint_action_skip_when_no_claude_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Skip);
    }

    #[test]
    fn hint_action_hint_when_claude_dir_exists_without_tools_json() {
        let tmp = tmp_with_claude();
        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Hint);
    }

    #[test]
    fn hint_action_hint_when_tools_json_without_guardrails() {
        let tmp = tmp_with_claude();
        fs::write(tmp.path().join(".claude/tools.json"), r#"{"reviews": {}}"#).unwrap();

        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Hint);
    }

    // The hook must not create or write to .claude/tools.json under any code path.
    // After running show_config_hint with a .claude/ present but tools.json absent,
    // the file must remain absent.
    #[test]
    fn hint_does_not_write_tools_json_when_absent() {
        let tmp = tmp_with_claude();
        let tools_path = tmp.path().join(TOOLS_CONFIG_FILE);
        assert!(!tools_path.exists(), "tools.json must be absent before");

        let config = Config {
            source: ConfigSource::Default,
            git_root: Some(tmp.path().to_path_buf()),
            ..Config::default()
        };
        show_config_hint(&config);

        assert!(
            !tools_path.exists(),
            "hook must not create tools.json, but found {}",
            tools_path.display()
        );
    }

    #[test]
    fn parse_stdin_from_accepts_valid_write_payload() {
        let json =
            r#"{"tool_name":"Write","tool_input":{"file_path":"/x.ts","content":"const x=1;"}}"#;
        let mut cursor = io::Cursor::new(json.as_bytes());
        match parse_stdin_from(&mut cursor) {
            Ok(parsed) => {
                assert_eq!(parsed.tool_name, "Write");
                assert_eq!(parsed.tool_input.file_path.as_deref(), Some("/x.ts"));
                assert_eq!(parsed.tool_input.content.as_deref(), Some("const x=1;"));
            }
            Err(e) => panic!("expected Ok, got Err({e:?})"),
        }
    }

    #[test]
    fn parse_stdin_from_rejects_invalid_json() {
        let mut cursor = io::Cursor::new(&b"not json"[..]);
        match parse_stdin_from(&mut cursor) {
            Err(e) => assert!(matches!(e, ParseStdinError::InvalidJson(_)), "got {e:?}"),
            Ok(_) => panic!("expected Err for invalid JSON"),
        }
    }

    #[test]
    fn parse_stdin_from_rejects_oversized_input() {
        let size = usize::try_from(MAX_INPUT_SIZE + 1).unwrap();
        let payload = vec![b'a'; size];
        let mut cursor = io::Cursor::new(payload);
        match parse_stdin_from(&mut cursor) {
            Err(e) => assert!(matches!(e, ParseStdinError::Oversized { .. }), "got {e:?}"),
            Ok(_) => panic!("expected Err for oversized input"),
        }
    }

    #[test]
    fn parse_stdin_error_into_payload_maps_error_codes() {
        assert_eq!(
            ParseStdinError::Io(io::Error::other("x"))
                .into_payload()
                .code,
            ErrorCode::IoError
        );
        assert_eq!(
            ParseStdinError::Oversized {
                cap: MAX_INPUT_SIZE
            }
            .into_payload()
            .code,
            ErrorCode::DataError
        );
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        assert_eq!(
            ParseStdinError::InvalidJson(json_err).into_payload().code,
            ErrorCode::DataError
        );
    }

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
    fn resolve_project_root_or_note_returns_path_and_skips_notes_on_ok() {
        let mut notes = Vec::new();
        let path = PathBuf::from("/some/path");
        let result = resolve_project_root_or_note(Ok(path.clone()), &mut notes);
        assert_eq!(result, Some(path));
        assert!(notes.is_empty(), "no note expected on Ok, got: {notes:?}");
    }

    #[test]
    fn resolve_project_root_or_note_pushes_note_on_err() {
        let mut notes = Vec::new();
        let err = io::Error::new(io::ErrorKind::NotFound, "no such dir");
        let result = resolve_project_root_or_note(Err(err), &mut notes);
        assert!(result.is_none(), "expected None on Err, got: {result:?}");
        assert_eq!(notes.len(), 1, "expected one note, got: {notes:?}");
        assert!(
            notes[0].contains("cannot resolve project root"),
            "note must describe failure; got: {}",
            notes[0]
        );
        assert!(
            notes[0].contains("no such dir"),
            "note must include underlying error; got: {}",
            notes[0]
        );
    }

    #[test]
    fn load_config_or_note_returns_config_and_skips_notes_on_ok() {
        let mut notes = Vec::new();
        let result = load_config_or_note(Ok(Config::default()), &mut notes);
        assert!(result.enabled);
        assert!(notes.is_empty(), "no note expected on Ok, got: {notes:?}");
    }

    #[test]
    fn load_config_or_note_pushes_note_and_falls_back_to_default_on_err() {
        let mut notes = Vec::new();
        let result = load_config_or_note(
            Err(String::from("invalid config \"x\": expected value")),
            &mut notes,
        );
        assert!(result.enabled, "fallback must be Config::default()");
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("config error"),
            "note must describe failure; got: {}",
            notes[0]
        );
        assert!(
            notes[0].contains("invalid config"),
            "note must include underlying error; got: {}",
            notes[0]
        );
    }
}
