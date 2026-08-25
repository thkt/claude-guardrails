//! Blocks an agent-driven edit to `.invariants.json` that weakens a declared
//! pin (drops a key or changes its value), independent of the `invariant`
//! content-comparison gate in `src/invariant.rs`. Deleting the pin file itself
//! is out of scope: guardrails only sees Write/Edit/MultiEdit tool input, not
//! `rm`.

use super::{rule_id, Severity, Violation};
use crate::invariant::{declaration_edit_weakens, is_declaration_path, INVARIANTS_FILE};
use crate::path_resolve::resolve_under_root;
use std::path::Path;

/// True when the edit targets the declaration file `load_invariant_table`
/// reads. Two spellings reach that file and neither check alone covers both:
/// `resolve_under_root` folds a lexical `..` back to a not-yet-existing
/// directory that `is_declaration_path` cannot resolve on disk, while
/// `is_declaration_path` alone catches a root-level `.invariants.json` that is
/// itself a symlink out of the repository.
fn is_invariants_declaration(file_path: &str, git_root: &Path) -> bool {
    let under_root = resolve_under_root(Path::new(file_path), git_root)
        .is_some_and(|resolved| resolved.relative == Path::new(INVARIANTS_FILE));
    under_root || is_declaration_path(file_path, git_root)
}

/// Note for an edit to `.invariants.json` whose post-edit content could not be
/// reconstructed. No content means no weakening can be judged, so the check
/// below never runs; without this note the skip would be silent.
pub(crate) fn degraded_note(file_path: &str, git_root: Option<&Path>) -> Option<String> {
    let git_root = git_root?;
    if !is_invariants_declaration(file_path, git_root) {
        return None;
    }
    Some(String::from(
        "`.invariants.json` post-edit content was not reconstructed; a weakened pin was not checked this edit.",
    ))
}

/// `Critical`, matching `config_guard`: a repository that raises
/// `blockThreshold` must not demote this to advisory, since the whole point is
/// stopping the self-editing bypass an AI agent could otherwise take against
/// its own pin.
pub(crate) fn check(
    file_path: &str,
    post_edit_content: &str,
    git_root: Option<&Path>,
) -> Vec<Violation> {
    let Some(git_root) = git_root else {
        return Vec::new();
    };
    if !is_invariants_declaration(file_path, git_root) {
        return Vec::new();
    }
    if !declaration_edit_weakens(git_root, post_edit_content) {
        return Vec::new();
    }
    vec![Violation {
        rule: rule_id::INVARIANT_GUARD.to_owned(),
        severity: Severity::Critical,
        fix: "This edit drops or changes a pinned value declared in `.invariants.json`. Leave the declaration to a human; ask for the change instead of editing this file."
            .to_owned(),
        file: file_path.to_owned(),
        line: None,
        origin: None,
        no_demote: None,
    }]
}

#[cfg(test)]
mod tests;
