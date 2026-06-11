//! Hook orchestration: parses stdin, resolves the project root and config,
//! runs the lint/AST/rule passes, partitions violations by severity, and maps
//! the outcome to a sysexits exit code.

use crate::analysis::{ast, ast_security, oxlint};
use crate::config::{Config, ConfigError};
use crate::content::{get_file_and_content, ToolInput, ToolName};
use crate::hook_exit::HookExitCode;
use crate::import_map;
use crate::io::output::{
    emit_human_violations, emit_json_if_enabled, render_error, show_config_hint,
};
use crate::io::stdin::parse_stdin;
use crate::rules::{self, non_comment_lines, Violation, ViolationOrigin};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

    let (vs, ns) = collect_first_party_violations(file_path, content, config, is_js);
    violations.extend(vs);
    notes.extend(ns);

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

fn partition_violations(
    violations: Vec<Violation>,
    config: &Config,
) -> (Vec<Violation>, Vec<Violation>) {
    violations
        .into_iter()
        .partition(|v| v.severity >= config.severity.block_threshold)
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

fn load_config_or_note(result: Result<Config, ConfigError>, notes: &mut Vec<String>) -> Config {
    match result {
        Ok(c) => c,
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

pub(crate) fn run_hook(json_mode: bool) -> i32 {
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
    F: FnOnce() -> Result<Config, ConfigError>,
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
        emit_json_if_enabled(json_mode, &[], &[], notes, Vec::new());
        return 0;
    };

    let config = load_config_or_note(load_config(), &mut notes);

    show_config_hint(&config);

    if !config.enabled {
        emit_json_if_enabled(json_mode, &[], &[], notes, Vec::new());
        return 0;
    }

    let (violations, lint_notes) = collect_violations(
        &target.file_path,
        &target.content,
        &config,
        project_root.as_deref(),
        target.is_js,
    );
    notes.extend(lint_notes);
    if let Some(reason) = target.degraded {
        let note = reason.note();
        eprintln!("guardrails: degraded: {note}");
        notes.push(note);
    }
    let (blocking, mut warnings) = partition_violations(violations, &config);
    let outcome =
        diff_aware::demote_preexisting(blocking, target, &config, project_root.as_deref());
    let (mut blocking, mut demoted) = (outcome.blocking, outcome.demoted);
    if let Some(n) = outcome.skip_note {
        notes.push(n);
    }
    let info_notes: Vec<String> = outcome.info_note.into_iter().collect();
    // Demoted violations pre-existed the edit; everything else the hook
    // reports (kept blocking and severity-routed warnings) charges to it.
    if config.diff_aware {
        for v in blocking.iter_mut().chain(warnings.iter_mut()) {
            v.origin = Some(ViolationOrigin::Introduced);
        }
        for v in &mut demoted {
            v.origin = Some(ViolationOrigin::Preexisting);
        }
    }
    warnings.extend(demoted);

    let blocking_refs: Vec<&Violation> = blocking.iter().collect();
    let warning_refs: Vec<&Violation> = warnings.iter().collect();
    emit_json_if_enabled(json_mode, &blocking_refs, &warning_refs, notes, info_notes);
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
