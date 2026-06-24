//! Semantic invariant gate: blocks an edit that silently mutates a value
//! declared immutable in a central `.invariants.json` (feature-flag bool,
//! i18n string, design token). Stateless conformance — the post-edit value is
//! compared against the declared scalar, with no git/diff/time baseline. The
//! human keeps the pin honest by editing `.invariants.json`; an AI edit that
//! drifts a pinned value is rejected in the same cycle. (#359)
//!
//! Scope is frontend runtime config/data JSON only (feature-flag / i18n /
//! design-token / public app config). `.json`-only is the mechanical scope:
//! infra (CIDR/YAML) is not `.json`, so `is_structured_config` rejects it
//! (deferred increment). Build config (tsconfig/package.json) is itself `.json`
//! and is not mechanically excluded; it stays out by convention, an OUTCOME
//! non-goal a human should not pin in `.invariants.json`.

use crate::rules::{rule_id, Severity, Violation};
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Central declaration file, read from the git root (same anchor as
/// `.guardrails.json`).
const INVARIANTS_FILE: &str = ".invariants.json";

/// One blocking invariant finding. `line` is `None` because a pin names a JSON
/// path, not a source line, in a file that may have been fully reconstructed.
fn violation(fix: String, file_path: &str) -> Violation {
    Violation {
        rule: String::from(rule_id::INVARIANT),
        severity: Severity::High,
        fix,
        file: String::from(file_path),
        line: None,
        origin: None,
    }
}

/// True when `path` names a structured-config file the invariant gate audits.
/// `.json` only: YAML and other formats are a later increment, mechanically
/// rejected here. Build config (tsconfig/package.json) is itself `.json` and
/// passes this gate; it stays out only by convention (an OUTCOME non-goal a
/// human should not pin), not by this check. `reconstruct_structured_full` in
/// `content.rs` gates on this and reuses the Edit/MultiEdit resolution with the
/// read gate forced open, so a `.json` Edit gets full post-edit content while
/// `is_js` stays false and existing content-scan rules keep seeing the snippet.
pub(crate) fn is_structured_config(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
}

/// Outcome of reading `.invariants.json`. `Skip` means "nothing to verify"
/// (absent, unreadable, or empty/whitespace-only — all fail-open). `Corrupt`
/// means the file has non-empty content that is not a JSON object — a tamper
/// signal that fails closed. `Table` carries the parsed pin declarations.
enum InvariantLoad {
    Skip,
    Corrupt,
    Table(Map<String, Value>),
}

/// Reads and classifies `.invariants.json` from the git root. A leading UTF-8
/// BOM and surrounding whitespace are stripped before parsing so a BOM-prefixed
/// or whitespace-padded file is not mistaken for a tamper. An empty or
/// whitespace-only file declares no pins, so it is `Skip` (fail-open) rather
/// than `Corrupt`: a human creating the file empty must not block every `.json`
/// edit in the repo. Only non-empty content that fails to parse as a JSON object
/// is `Corrupt`.
fn load_invariant_table(git_root: &Path) -> InvariantLoad {
    let invariants_path = git_root.join(INVARIANTS_FILE);
    let Ok(raw) = fs::read_to_string(&invariants_path) else {
        return InvariantLoad::Skip;
    };
    let trimmed = raw.strip_prefix('\u{feff}').unwrap_or(&raw).trim();
    if trimmed.is_empty() {
        return InvariantLoad::Skip;
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Object(map)) => InvariantLoad::Table(map),
        _ => InvariantLoad::Corrupt,
    }
}

/// Derives the git-root-relative pin key from the same resolved path the content
/// read used. `content.rs` canonicalizes `file_path` before reading, so deriving
/// the key from the raw path would silently mismatch when an ancestor is a
/// symlink (the read succeeds, the pin lookup misses, the mutation passes
/// unchecked). The canonicalized pair is tried first; it wins whenever both the
/// git root and the file's parent resolve. When either cannot be resolved (e.g.
/// a new file whose parent does not exist yet at `PreToolUse`), the raw pair is
/// used so the gate is never stricter than the raw-path lookup it replaces.
/// Returns `None` when the path is not under the git root by either pairing,
/// which includes a bare/relative `file_path` (no resolvable parent): the gate
/// fails open rather than guess a key. Tool input always supplies absolute paths,
/// so this is an edge guard, not the production path.
fn canonical_relative_key(file_path: &str, git_root: &Path) -> Option<String> {
    if let (Ok(canonical_root), Some(resolved)) =
        (fs::canonicalize(git_root), canonical_path(file_path))
    {
        if let Ok(relative) = resolved.strip_prefix(&canonical_root) {
            return Some(relative.to_string_lossy().into_owned());
        }
    }
    let relative = Path::new(file_path).strip_prefix(git_root).ok()?;
    Some(relative.to_string_lossy().into_owned())
}

/// Canonicalizes a path whose final component may not exist yet (a `Write` of a
/// new file at PreToolUse): the parent directory is canonicalized and the file
/// name rejoined, collapsing symlinked ancestors into the same space as the
/// canonicalized git root.
fn canonical_path(file_path: &str) -> Option<PathBuf> {
    let path = Path::new(file_path);
    let parent = path.parent()?;
    let name = path.file_name()?;
    let canonical_parent = fs::canonicalize(parent).ok()?;
    Some(canonical_parent.join(name))
}

/// Orchestrates the invariant self-gate over a single post-edit file, returning
/// the violations (empty when the gate skips). The `config.rules.invariant`
/// toggle is checked by the caller before this runs.
///
/// Order honors NFR-001: `structured_full` (None for non-`.json` or failed
/// reconstruction) short-circuits before any `.invariants.json` disk read, so a
/// `.ts/.css/.md` edit pays nothing.
pub(crate) fn run_invariant_pass(
    file_path: &str,
    structured_full: Option<&str>,
    git_root: Option<&Path>,
) -> Vec<Violation> {
    // No reconstructed full content (non-`.json` or reconstruction failed): the
    // gate has nothing to compare, so skip before touching the disk (NFR-001).
    let Some(content) = structured_full else {
        return Vec::new();
    };
    // Without a git root there is no anchor for `.invariants.json`.
    let Some(git_root) = git_root else {
        return Vec::new();
    };

    // Absent / unreadable / empty pin file means nothing is pinned: skip
    // (fail-open). Only non-empty, non-object content fails closed, so a
    // corrupted pin file cannot silently disable the gate.
    let table = match load_invariant_table(git_root) {
        InvariantLoad::Skip => return Vec::new(),
        InvariantLoad::Corrupt => {
            return vec![violation(
                String::from(".invariants.json is not a valid JSON object; pinned values cannot be verified."),
                file_path,
            )];
        }
        InvariantLoad::Table(map) => map,
    };

    // The declaration is keyed by git-root-relative path, resolved through the
    // same canonicalization the content read used. An edit outside the git root
    // (or one whose relative key is not declared) is not pinned: skip.
    let Some(relative_key) = canonical_relative_key(file_path, git_root) else {
        return Vec::new();
    };
    let Some(declared) = table.get(&relative_key) else {
        return Vec::new();
    };

    let Value::Object(pins) = declared else {
        return vec![violation(
            format!(
                "`.invariants.json` entry for `{relative_key}` must be an object mapping pinned paths to scalars."
            ),
            file_path,
        )];
    };

    check_invariants(pins, content, file_path)
}

/// Pure conformance check: for each declared pin, resolve its dot-path in the
/// post-edit `content` and compare against the declared scalar. A mismatch, an
/// unresolved path, or a non-scalar declaration is a violation. Unparseable
/// `content` fails closed (one violation) since a tamper could have broken it.
pub(crate) fn check_invariants(
    declared: &Map<String, Value>,
    content: &str,
    file_path: &str,
) -> Vec<Violation> {
    // Edited file that no longer parses as JSON: a tamper could have broken it,
    // so fail closed rather than skip the pinned values it should still hold.
    let Ok(document) = serde_json::from_str::<Value>(content) else {
        return vec![violation(
            String::from("edited file is not valid JSON; pinned values cannot be verified. Restore valid JSON."),
            file_path,
        )];
    };

    let mut violations = Vec::new();
    for (dot_path, expected) in declared {
        if expected.is_object() || expected.is_array() {
            violations.push(violation(
                format!(
                    "pinned path `{dot_path}` declares a non-scalar value; only bool, number, string, and null can be pinned."
                ),
                file_path,
            ));
            continue;
        }

        match resolve(&document, dot_path) {
            None => violations.push(violation(
                format!("pinned path `{dot_path}` is absent from the edited file. Restore it."),
                file_path,
            )),
            Some(actual) if actual != expected => violations.push(violation(
                format!(
                    "pinned value at `{dot_path}` changed to {actual}; it is fixed at {expected}. Restore the fixed value."
                ),
                file_path,
            )),
            Some(_) => {}
        }
    }
    violations
}

/// Resolves a declared `dot_path` against the parsed document. A flat literal
/// key (`{"a.b": ...}`) is preferred over a nested descent (`{"a": {"b": ...}}`)
/// so a key that legitimately contains dots can be pinned directly; only when no
/// flat key exists does the path split on `.` and descend object by object.
fn resolve<'a>(document: &'a Value, dot_path: &str) -> Option<&'a Value> {
    if let Some(value) = document.get(dot_path) {
        return Some(value);
    }
    let mut current = document;
    for segment in dot_path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Builds a note for a pinned `.json` whose post-edit content could not be
/// reconstructed (oversize, non-UTF8, IO error), so the invariant pass received
/// no content and skipped it. Returns `None` when the file is not pinned
/// (nothing to verify, so no note) or when there is no git root. The note states
/// the skip without blocking: blocking on an unreadable file would re-create the
/// repo-wide false-block that fail-open is meant to avoid.
///
/// The note deliberately omits the degraded *reason*: this gate guards an
/// integrity boundary, and naming the trigger (e.g. an oversize file) in
/// agent-visible output would hand an AI editor the exact lever to pad a file
/// past the read cap and slip a pinned-value change past the skip. The human is
/// pointed at the declaration to re-verify by hand instead.
pub(crate) fn degraded_note(file_path: &str, git_root: Option<&Path>) -> Option<String> {
    let git_root = git_root?;
    match load_invariant_table(git_root) {
        // Nothing pinned: a degraded read of an unpinned-repo file has nothing to
        // report, so stay silent.
        InvariantLoad::Skip => None,
        // A corrupt declaration file normally fails closed in `run_invariant_pass`,
        // but that path is gated on reconstructed content, which a degraded read
        // does not have. Surfacing it here keeps the corrupt-pin signal from
        // vanishing silently when the edited `.json` is also unreadable.
        InvariantLoad::Corrupt => Some(String::from(
            ".invariants.json is not a valid JSON object; pinned values were not verified this edit.",
        )),
        InvariantLoad::Table(table) => {
            let relative_key = canonical_relative_key(file_path, git_root)?;
            table.get(&relative_key)?;
            Some(format!(
                "pinned `{relative_key}` was not verified this edit; review the change against `.invariants.json` by hand."
            ))
        }
    }
}

#[cfg(test)]
mod tests;
