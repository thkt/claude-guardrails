//! Blocks an agent-driven edit to `.invariants.json` that weakens a declared
//! pin (drops a key or changes its value), independent of the `invariant`
//! content-comparison gate in `src/invariant.rs`. Deleting the pin file itself
//! is out of scope: guardrails only sees Write/Edit/MultiEdit tool input, not
//! `rm` (#451).

use super::{rule_id, Severity, Violation};
use crate::invariant::{declaration_edit_weakens, INVARIANTS_FILE};
use crate::path_resolve::resolve_under_root;
use std::path::Path;

/// A raw comparison would miss a `file_path` spelled through a symlink, the
/// same reason `config_guard::is_guardrails_config` resolves before
/// comparing.
fn is_invariants_declaration(file_path: &str, git_root: &Path) -> bool {
    let Some(resolved) = resolve_under_root(Path::new(file_path), git_root) else {
        return false;
    };
    resolved.relative == Path::new(INVARIANTS_FILE)
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
    }]
}

#[cfg(test)]
mod tests;
