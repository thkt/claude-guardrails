//! Hook orchestration: parses stdin, resolves the project root and config,
//! runs the lint/AST/rule passes, partitions violations by severity, and maps
//! the outcome to a sysexits exit code.

use crate::analysis::ast_rules::{self, AstRequest, AstRuleFlags};
use crate::analysis::{ast_security, nesting, oxlint};
use crate::config::{Config, ConfigError};
use crate::content::{get_file_and_content, ContentResolution, ToolInput, ToolName};
use crate::hook_exit::HookExitCode;
use crate::invariant::{degraded_note, run_invariant_pass};
use crate::io::output::{
    emit_hook_context, emit_human_violations, emit_json_if_enabled, hook_specific_output,
    render_error, show_config_hint, JsonEmission,
};
use crate::io::stdin::parse_stdin;
use crate::rules::{self, non_comment_lines, Severity, Violation, ViolationOrigin};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// Outcome of running the six structural AST rules, from whichever path
/// produced it (in-process under test, or the child subprocess in production).
enum AstOutcome {
    /// Parse succeeded; these are the structural violations (possibly empty).
    Violations(Vec<Violation>),
    /// Parse failed (unsupported type or parser panic). Structural rules are
    /// skipped and the edit proceeds with a note — the #294 fail-open contract.
    ParseFailed,
    /// The child checker failed before completing every structural rule. Block
    /// the edit rather than treating an incomplete check as a parse failure.
    InternalFailure,
    /// The parse aborted on a stack overflow the byte scan could not see (deep
    /// JSX / ternary / generics). Block the edit (#314).
    Overflow,
}

fn lint_with_ast(
    content: &str,
    file_path: &str,
    config: &Config,
) -> (Vec<Violation>, Option<String>) {
    // The parse fires whenever ANY of the seven AST rules is on. `AstRuleFlags`
    // is the single source for that set, so the early-return, the child request,
    // and the in-process call cannot drift apart (the lockstep that motivated
    // removing the old outer `has_ast_rules` guard).
    let flags = AstRuleFlags::from_config(config);
    if !flags.any() {
        return (Vec::new(), None);
    }
    // check_bidi is a pure byte scan with no AST dependency. Run it before the
    // parse so a parse failure (panic / unsupported type) cannot skip the most
    // important security check — the fail-open fixed in #294.
    let mut found = Vec::new();
    if config.rules.ast_security {
        if let Some(v) = ast_security::check_bidi(content, file_path) {
            found.push(v);
        }
    }
    // Pre-parse depth guard (#314), tier 1: deeply nested brackets / prefix runs
    // overflow oxc's recursive-descent parser and abort (exit 134 = fail-open).
    // This deterministic byte scan blocks them before the parse with zero false
    // positives. Unconditional (not gated on ast_security) because the parse
    // runs on any of the seven rules; gating it would let {ast_security:false,
    // eval:true} reach the parse unguarded and abort.
    if let Some(v) = nesting::check_excessive_nesting(content, file_path) {
        // No note: unlike a parse failure (which silently drops structural
        // rules while the edit still proceeds = degraded coverage), this is
        // a deliberate block. The High Violation rejects the edit (exit 2),
        // so the skipped structural rules are moot.
        found.push(v);
        return (found, None);
    }
    // Tier 2: run the parse + structural rules in a child process so an overflow
    // the byte scan cannot see (deep JSX / ternary / generics carry no bracket
    // signature) aborts the child, not the hook. The child re-execs this same
    // binary with the same stack, so it aborts exactly when an in-process parse
    // would. Under cfg!(test) the test binary's entry point cannot dispatch the
    // child subcommand, so unit tests use the in-process path — their inputs
    // never reach the overflow floor, so they never abort the test runner.
    let outcome = if cfg!(test) {
        run_ast_inprocess(content, file_path, &flags)
    } else {
        spawn_ast_child(content, file_path, &flags)
    };
    match outcome {
        AstOutcome::Violations(v) => {
            found.extend(v);
            (found, None)
        }
        AstOutcome::ParseFailed => (
            found,
            // check_bidi already ran above, so any bidi violation is in `found`;
            // only the AST-dependent (structural) rules were skipped.
            Some(String::from(
                "AST parse failed; structural rules skipped (bidi scan still applied)",
            )),
        ),
        AstOutcome::InternalFailure => {
            found.push(ast_checker_failure_violation(file_path));
            (found, None)
        }
        AstOutcome::Overflow => {
            found.push(nesting::overflow_violation(file_path));
            (found, None)
        }
    }
}

fn run_ast_inprocess(content: &str, file_path: &str, flags: &AstRuleFlags) -> AstOutcome {
    match ast_rules::run_ast_rules(content, file_path, flags) {
        Some(v) => AstOutcome::Violations(v),
        None => AstOutcome::ParseFailed,
    }
}

/// Classifies a child that did not produce a successful violation payload.
/// Exit 1 is the explicit parse-failure contract; a signal death is the parser
/// overflow contract; every other exit code is an internal checker failure.
fn classify_ast_child_failure(exit_code: Option<i32>) -> AstOutcome {
    match exit_code {
        Some(1) => AstOutcome::ParseFailed,
        Some(_) => AstOutcome::InternalFailure,
        None => AstOutcome::Overflow,
    }
}

fn ast_checker_failure_violation(file_path: &str) -> Violation {
    Violation {
        rule: rules::rule_id::AST_CHECKER_INTERNAL_FAILURE.to_owned(),
        severity: Severity::High,
        fix: String::from(
            "The checker failed before completing every structural rule; resolve the internal checker error and retry.",
        ),
        file: file_path.to_owned(),
        line: None,
        origin: None,
        no_demote: None,
    }
}

/// Spawns the hidden `__ast-child` subcommand to parse in isolation. Every
/// spawn-time failure (serialize, `current_exe`, spawn) fails closed
/// (`Overflow` → block): falling back to the in-process parse here would re-open
/// the exact #314 fail-open, because a byte-scan-invisible overflow input would
/// then abort the hook (exit 134, non-blocking). A spawn failure is
/// environmental and astronomically rare; blocking on it is the safe direction.
fn spawn_ast_child(content: &str, file_path: &str, flags: &AstRuleFlags) -> AstOutcome {
    let request = AstRequest {
        content: content.to_owned(),
        file_path: file_path.to_owned(),
        flags: flags.clone(),
    };
    let Ok(payload) = serde_json::to_vec(&request) else {
        return AstOutcome::Overflow;
    };
    let Ok(exe) = env::current_exe() else {
        return AstOutcome::Overflow;
    };
    let spawned = Command::new(exe)
        .arg("__ast-child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return AstOutcome::Overflow;
    };
    if let Some(mut stdin) = child.stdin.take() {
        // Ignore write errors: a child that aborts before draining stdin closes
        // the pipe (EPIPE). The exit code below is the source of truth, so do
        // not unwrap — unwrapping would crash the hook on the very overflow this
        // path exists to contain.
        let _ = stdin.write_all(&payload);
    }
    // stdin dropped here → EOF for the child's read_to_string.
    let Ok(output) = child.wait_with_output() else {
        return AstOutcome::Overflow;
    };
    match output.status.code() {
        Some(0) => match serde_json::from_slice::<Vec<Violation>>(&output.stdout) {
            Ok(v) => AstOutcome::Violations(v),
            // Exit 0 means the child encoded a valid Vec<Violation> and wrote
            // nothing else (its only stdout write is that one line), so an
            // undecodable payload is an unreachable contract breach. Fail closed:
            // proceeding here would silently drop any violation the child found.
            Err(_) => AstOutcome::InternalFailure,
        },
        code => classify_ast_child_failure(code),
    }
}

fn collect_violations(
    file_path: &str,
    content: &str,
    config: &Config,
    project_root: Option<&Path>,
    is_js: bool,
    structured_full: Option<&str>,
) -> (Vec<Violation>, Vec<String>) {
    let mut violations = Vec::new();
    let mut notes = Vec::new();

    if is_js {
        let (vs, ns) = lint_with_external_tools(content, file_path, config, project_root);
        violations.extend(vs);
        notes.extend(ns);
    }

    let (vs, ns) = collect_first_party_violations(file_path, content, config, is_js);
    violations.extend(vs);
    notes.extend(ns);

    // Invariant gate runs independent of is_js (it audits `.json`); the toggle
    // gates step 1, the pass short-circuits on `structured_full = None` before
    // any `.invariants.json` read.
    if config.rules.invariant {
        violations.extend(run_invariant_pass(
            file_path,
            structured_full,
            config.git_root.as_deref(),
        ));
    }

    // Not gated on is_js or on the content resolution: the check is the path.
    if config.rules.config_guard {
        violations.extend(rules::config_guard::check(
            file_path,
            config.git_root.as_deref(),
        ));
    }

    // Guards the declaration file itself, not a pinned value drifting in the
    // file it declares. Gated on `structured_full` because a weakening edit can
    // only be judged from the reconstructed post-edit content.
    if config.rules.invariant {
        if let Some(content) = structured_full {
            violations.extend(rules::invariant_guard::check(
                file_path,
                content,
                config.git_root.as_deref(),
            ));
        }
    }

    (violations, notes)
}

/// First-party passes only (line rules + AST), no oxlint subprocess. The
/// diff-aware before pass runs this directly so its sole note source is an
/// AST parse failure, keeping the demotion-abort contract narrow.
fn collect_first_party_violations(
    file_path: &str,
    content: &str,
    config: &Config,
    is_js: bool,
) -> (Vec<Violation>, Vec<String>) {
    let mut violations = Vec::new();
    let mut notes = Vec::new();

    let masked = rules::comment_masked_source(content);
    let lines = non_comment_lines(&masked);
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

/// Rules on ADR-0004's resource-boundary axis, which that ADR marks fail-closed
/// and not bypassable by adversarial input. They skip `block_threshold`: a
/// project raising it must not be able to switch off a guard that exists so a
/// hostile input cannot crash the checker before any rule runs (#474).
const RESOURCE_BOUNDARY_RULES: &[&str] = &[
    rules::rule_id::EXCESSIVE_NESTING,
    rules::rule_id::AST_CHECKER_INTERNAL_FAILURE,
];

fn partition_violations(
    violations: Vec<Violation>,
    config: &Config,
) -> (Vec<Violation>, Vec<Violation>) {
    violations.into_iter().partition(|v| {
        RESOURCE_BOUNDARY_RULES.contains(&v.rule.as_str())
            || v.severity >= config.severity.block_threshold
    })
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

fn load_config_or_note(
    result: Result<(Config, Vec<String>), ConfigError>,
    notes: &mut Vec<String>,
) -> Config {
    match result {
        Ok((c, load_notes)) => {
            emit_notes(load_notes, notes);
            c
        }
        Err(e) => {
            let note = format!(
                "config error (using defaults: all rules enabled, block_threshold=high): {e}"
            );
            eprintln!("guardrails: {note}");
            notes.push(note);
            Config::default()
        }
    }
}

/// Echoes each note to stderr on top of appending it. Without the echo a note
/// rides the JSON envelope alone, which hook mode does not emit, leaving the
/// human reading a debug log nothing to go on.
fn emit_notes(new_notes: Vec<String>, notes: &mut Vec<String>) {
    for note in &new_notes {
        eprintln!("guardrails: {note}");
    }
    notes.extend(new_notes);
}

/// Layers the toggles effective for `file_path` onto `config.rules`, right
/// after config load and before `collect_violations` reads one.
/// `AstRuleFlags::from_config` (the `ast_security` / eval / ... gate sitting
/// outside `rules::load_rules`) runs inside `collect_violations`, so resolving
/// here — ahead of both gates — is the one point covering a registry rule
/// (`sensitive-file`) and a rule gated outside the registry (`ast_security`)
/// alike.
fn resolve_effective_rules_with_notes(
    mut config: Config,
    file_path: &str,
    notes: &mut Vec<String>,
) -> Config {
    let (rules, override_notes) = config.effective_rules_with_notes(file_path);
    emit_notes(override_notes, notes);
    config.rules = rules;
    config
}

pub(crate) fn run_hook(json_mode: bool) -> i32 {
    let input = match parse_stdin() {
        Ok(v) => v,
        Err(e) => {
            let exit = e.hook_exit_code();
            render_error(json_mode, e.into_payload());
            return i32::from(exit.code());
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
    F: FnOnce() -> Result<(Config, Vec<String>), ConfigError>,
{
    let mut notes = Vec::new();
    let project_root = resolve_project_root_or_note(project_root_result, &mut notes);

    let Some(target) = get_file_and_content(input, project_root.as_deref()) else {
        let is_write_tool = matches!(
            input.tool_name,
            ToolName::Write | ToolName::Edit | ToolName::MultiEdit
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
        emit_json_if_enabled(
            json_mode,
            JsonEmission {
                notes,
                ..Default::default()
            },
        );
        return 0;
    };

    let config = load_config_or_note(load_config(), &mut notes);
    let config = resolve_effective_rules_with_notes(config, &target.file_path, &mut notes);

    show_config_hint(&config);

    if !config.enabled {
        emit_json_if_enabled(
            json_mode,
            JsonEmission {
                notes,
                ..Default::default()
            },
        );
        return 0;
    }

    let (violations, lint_notes) = collect_violations(
        &target.file_path,
        &target.content,
        &config,
        project_root.as_deref(),
        target.is_js,
        target.structured_full.as_full_str(),
    );
    notes.extend(lint_notes);
    // A `.json` whose post-edit content could not be reconstructed (oversize,
    // non-UTF8, IO error) reaches the invariant pass as `None` and is skipped.
    // When the file is actually pinned, surface a note so the skip is visible
    // instead of silent; an unpinned file stays quiet.
    if config.rules.invariant {
        if let ContentResolution::Degraded(_) = &target.structured_full {
            let pin_note = degraded_note(&target.file_path, config.git_root.as_deref());
            let guard_note = rules::invariant_guard::degraded_note(
                &target.file_path,
                config.git_root.as_deref(),
            );
            for note in pin_note.into_iter().chain(guard_note) {
                eprintln!("guardrails: invariant: {note}");
                notes.push(note);
            }
        }
    }
    if let Some(reason) = target.degraded {
        let note = reason.note();
        eprintln!("guardrails: degraded: {note}");
        notes.push(note);
    }
    let (blocking, mut warnings) = partition_violations(violations, &config);
    let outcome =
        diff_aware::demote_preexisting(blocking, target, &config, project_root.as_deref());
    let (blocking, mut demoted) = (outcome.blocking, outcome.demoted);
    if let Some(n) = outcome.skip_note {
        notes.push(n);
    }
    let info_notes: Vec<String> = outcome.info_note.into_iter().collect();
    // Demoted violations pre-existed the edit, verified by before-comparison.
    // Everything else stays origin-less: the hook cannot prove a survivor was
    // introduced (non-allowlisted rules are not before-compared), so it makes
    // no claim. demoted is empty unless the diff-aware toggle is on.
    for v in &mut demoted {
        v.origin = Some(ViolationOrigin::Preexisting);
    }
    warnings.extend(demoted);

    let blocking_refs: Vec<&Violation> = blocking.iter().collect();
    let warning_refs: Vec<&Violation> = warnings.iter().collect();
    let hook_output = hook_specific_output(&blocking_refs, &warning_refs, &notes);
    emit_hook_context(json_mode, hook_output.as_ref());
    emit_json_if_enabled(
        json_mode,
        JsonEmission {
            blocking: &blocking_refs,
            warnings: &warning_refs,
            notes,
            info_notes,
            hook_specific_output: hook_output,
        },
    );
    emit_human_violations(&blocking_refs, &warning_refs);
    let outcome = if !blocking.is_empty() {
        HookExitCode::Blocking
    } else if !warnings.is_empty() {
        HookExitCode::Advisory
    } else {
        HookExitCode::Pass
    };
    i32::from(outcome.code())
}

#[cfg(test)]
mod demotion_surface;
mod diff_aware;
#[cfg(test)]
mod precision;
#[cfg(test)]
mod tests;
