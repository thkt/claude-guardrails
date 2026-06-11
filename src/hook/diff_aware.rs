//! Demotion classifier: blocking violations that already existed in the
//! before-edit content demote to advisory; everything else keeps blocking.

use crate::config::Config;
use crate::content::{
    read_file_capped, BeforeSource, ContentResolution, DegradedReason, ResolvedTarget,
};
use crate::rules::Violation;
use std::collections::HashMap;
use std::path::Path;

/// Rules eligible for demotion. Enrollment requires all three: the rule
/// reports every occurrence, decides each violation from a single line, and
/// reports the line whose text alone reproduces the violation.
pub(crate) const DEMOTABLE_RULES: &[&str] = &["eval"];

/// Gate for the second pass: lint the before-edit content only when the
/// toggle is on and at least one blocking violation could actually demote.
pub(crate) fn demotion_eligible(diff_aware: bool, blocking: &[Violation]) -> bool {
    diff_aware && blocking.iter().any(|v| allowlist_entry(&v.rule).is_some())
}

/// Demotes blocking violations that already existed in the before-edit
/// content. Returns (kept blocking, demoted, skip note). Fail-safe: any
/// uncertainty about the before content keeps every violation blocking and
/// says why in the note; a missing file is the legitimate new-file case and
/// keeps all without a note.
pub(crate) fn demote_preexisting(
    blocking: Vec<Violation>,
    target: ResolvedTarget,
    config: &Config,
    project_root: Option<&Path>,
) -> (Vec<Violation>, Vec<Violation>, Option<String>) {
    if !demotion_eligible(config.diff_aware, &blocking) {
        return (blocking, Vec::new(), None);
    }
    if target.degraded.is_some() {
        return keep_all(blocking, "content resolution degraded");
    }
    let before_content = match target.before {
        BeforeSource::Retained(s) => s,
        BeforeSource::OnDisk => {
            match read_file_capped(&target.file_path, project_root, target.is_js) {
                ContentResolution::Full(c) => c,
                ContentResolution::Degraded(DegradedReason::FileNotFound) => {
                    return (blocking, Vec::new(), None);
                }
                ContentResolution::Degraded(reason) => {
                    return keep_all(blocking, read_failure_phrase(reason));
                }
                ContentResolution::NotApplicable => {
                    return keep_all(blocking, "before-edit content unavailable");
                }
            }
        }
        BeforeSource::Unavailable => {
            return keep_all(blocking, "before-edit content unavailable");
        }
    };
    let (before_violations, before_notes) = super::collect_first_party_violations(
        &target.file_path,
        &before_content,
        config,
        target.is_js,
    );
    if !before_notes.is_empty() {
        return keep_all(
            blocking,
            &format!("before-edit lint incomplete: {}", before_notes.join("; ")),
        );
    }
    let result = classify(
        blocking,
        &target.content,
        &before_violations,
        &before_content,
    );
    (result.blocking, result.demoted, None)
}

fn keep_all(
    blocking: Vec<Violation>,
    why: &str,
) -> (Vec<Violation>, Vec<Violation>, Option<String>) {
    (
        blocking,
        Vec::new(),
        Some(format!(
            "demotion skipped ({why}); pre-existing violations kept blocking"
        )),
    )
}

fn read_failure_phrase(reason: DegradedReason) -> &'static str {
    match reason {
        DegradedReason::PermissionDenied => "permission denied reading before-edit file",
        _ => "cannot read before-edit file",
    }
}

pub(crate) struct Classification {
    pub(crate) blocking: Vec<Violation>,
    pub(crate) demoted: Vec<Violation>,
}

/// Partitions blocking violations into demoted (already present in the
/// before-edit content) and still-blocking. Identity is (rule, trimmed line
/// text) counted as a multiset, so demotion is capped at the before-count and
/// a pasted extra copy keeps blocking. Anything that cannot be matched
/// (non-allowlisted rule, missing line number, line out of range) keeps
/// blocking; the fail-safe direction is over-blocking, never over-demoting.
pub(crate) fn classify(
    blocking: Vec<Violation>,
    after_content: &str,
    before_violations: &[Violation],
    before_content: &str,
) -> Classification {
    let mut budget: HashMap<(&str, &str), usize> = HashMap::new();
    for v in before_violations {
        let Some(rule) = allowlist_entry(&v.rule) else {
            continue;
        };
        let Some(text) = v.line.and_then(|line| line_text(before_content, line)) else {
            continue;
        };
        *budget.entry((rule, text)).or_insert(0) += 1;
    }

    let mut kept = Vec::new();
    let mut demoted = Vec::new();
    for v in blocking {
        let preexisting = allowlist_entry(&v.rule).is_some_and(|rule| {
            v.line
                .and_then(|line| line_text(after_content, line))
                .is_some_and(|text| match budget.get_mut(&(rule, text)) {
                    Some(count) if *count > 0 => {
                        *count -= 1;
                        true
                    }
                    _ => false,
                })
        });
        if preexisting {
            demoted.push(v);
        } else {
            kept.push(v);
        }
    }
    Classification {
        blocking: kept,
        demoted,
    }
}

/// The `'static` return decouples budget keys from the violation borrow.
fn allowlist_entry(rule: &str) -> Option<&'static str> {
    DEMOTABLE_RULES.iter().find(|r| **r == rule).copied()
}

fn line_text(content: &str, line: u32) -> Option<&str> {
    let idx = (line as usize).checked_sub(1)?;
    content.lines().nth(idx).map(str::trim)
}

#[cfg(test)]
mod tests;
