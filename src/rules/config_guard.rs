//! Blocks an agent-driven edit to the config files guardrails itself reads.
//!
//! An agent that rewrites the config switches off the rule that would stop its
//! next edit, and an `overrides` entry reads as a test-path exclusion.

use super::{rule_id, Severity, Violation};
use crate::config::{GUARDRAILS_CONFIG_FILE, LEGACY_CONFIG_FILE, TOOLS_CONFIG_FILE};
use crate::path_resolve::resolve_under_root;
use std::path::Path;

/// A raw comparison would miss a `file_path` spelled through a symlink: the
/// git root arrives resolved, the spelling does not. A nested
/// `.guardrails.json` stays unguarded either way, since
/// `with_overrides_from_root` reads the copies at the git root alone.
fn is_guardrails_config(file_path: &str, git_root: &Path) -> bool {
    let Some(resolved) = resolve_under_root(Path::new(file_path), git_root) else {
        return false;
    };
    [
        GUARDRAILS_CONFIG_FILE,
        TOOLS_CONFIG_FILE,
        LEGACY_CONFIG_FILE,
    ]
    .iter()
    .any(|name| resolved.relative == Path::new(name))
}

/// `Critical`, not `High`: a repository that raises `blockThreshold` to
/// `critical` would otherwise demote this to advisory and reopen the bypass.
pub(crate) fn check(file_path: &str, git_root: Option<&Path>) -> Vec<Violation> {
    let Some(git_root) = git_root else {
        return Vec::new();
    };
    if !is_guardrails_config(file_path, git_root) {
        return Vec::new();
    }
    vec![Violation {
        rule: rule_id::CONFIG_GUARD.to_owned(),
        severity: Severity::Critical,
        fix: "Leave guardrails config to a human. Ask for the change instead of editing this file."
            .to_owned(),
        file: file_path.to_owned(),
        line: None,
        origin: None,
    }]
}

#[cfg(test)]
mod tests;
