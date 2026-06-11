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
/// reports the line whose text alone reproduces the violation. Those
/// properties are pinned per enrolled rule by
/// `allowlisted_rules_report_every_occurrence` and the demotion-surface
/// corpus tests, which fail when a rule enrolls without matching entries.
pub(crate) const DEMOTABLE_RULES: &[&str] = &["eval"];

/// Gate for the second pass: lint the before-edit content only when the
/// toggle is on and at least one blocking violation could actually demote.
pub(crate) fn demotion_eligible(diff_aware: bool, blocking: &[Violation]) -> bool {
    diff_aware && blocking.iter().any(|v| allowlist_entry(&v.rule).is_some())
}

pub(crate) struct DemotionOutcome {
    pub(crate) blocking: Vec<Violation>,
    pub(crate) demoted: Vec<Violation>,
    /// Degradation note: demotion was skipped and why. Drives `degraded`.
    pub(crate) skip_note: Option<String>,
    /// Count report for a completed second pass (zero included). Never
    /// drives `degraded`.
    pub(crate) info_note: Option<String>,
}

impl DemotionOutcome {
    fn unchanged(blocking: Vec<Violation>) -> Self {
        Self {
            blocking,
            demoted: Vec::new(),
            skip_note: None,
            info_note: None,
        }
    }
}

/// Demotes blocking violations that already existed in the before-edit
/// content. Fail-safe: any uncertainty about the before content keeps every
/// violation blocking and says why in the skip note; a missing file is the
/// legitimate new-file case and keeps all without a note. The before pass
/// reuses the same `Config` as the after pass, so both sides lint with an
/// identical rule set and the (rule, line text) match stays symmetric.
pub(crate) fn demote_preexisting(
    blocking: Vec<Violation>,
    target: ResolvedTarget,
    config: &Config,
    project_root: Option<&Path>,
) -> DemotionOutcome {
    if !demotion_eligible(config.diff_aware, &blocking) {
        return DemotionOutcome::unchanged(blocking);
    }
    if target.degraded.is_some() {
        return keep_all(blocking, "content resolution degraded");
    }
    let before_content = match target.before {
        BeforeSource::Retained(s) => s,
        BeforeSource::OnDisk => {
            // Without a resolved project root the path-boundary check inside
            // `read_file_capped` is disabled, so reading at all would let a
            // file outside the (unknown) project drive demotion. Skip the
            // read entirely; fail-safe direction is over-blocking.
            let Some(root) = project_root else {
                return keep_all(
                    blocking,
                    "cannot verify before-edit file is inside the project",
                );
            };
            match read_file_capped(&target.file_path, Some(root), target.is_js) {
                ContentResolution::Full(c) => c,
                ContentResolution::Degraded(DegradedReason::FileNotFound) => {
                    return DemotionOutcome::unchanged(blocking);
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
    let info_note = format!(
        "diff-aware: {} pre-existing violation(s) demoted to advisory",
        result.demoted.len()
    );
    DemotionOutcome {
        blocking: result.blocking,
        demoted: result.demoted,
        skip_note: None,
        info_note: Some(info_note),
    }
}

fn keep_all(blocking: Vec<Violation>, why: &str) -> DemotionOutcome {
    DemotionOutcome {
        blocking,
        demoted: Vec::new(),
        skip_note: Some(format!(
            "demotion skipped ({why}); pre-existing violations kept blocking"
        )),
        info_note: None,
    }
}

/// Exhaustive on purpose: a new `DegradedReason` variant must fail to compile
/// here so it gets a deliberate phrase instead of a silent catch-all.
fn read_failure_phrase(reason: DegradedReason) -> &'static str {
    match reason {
        DegradedReason::OversizedFile => "before-edit file exceeds size limit",
        DegradedReason::NonUtf8Content => "before-edit file is not valid UTF-8",
        DegradedReason::FileNotFound => "before-edit file not found",
        DegradedReason::PermissionDenied => "permission denied reading before-edit file",
        DegradedReason::IoError => "i/o error reading before-edit file",
        DegradedReason::PathOutsideProject => "before-edit file resolves outside the project root",
        // Edit-resolution failures cannot reach the on-disk read, but the
        // fail-safe answer is still a phrase rather than a panic.
        DegradedReason::OldStringNotFound | DegradedReason::MultiEditMidFailure(_) => {
            "cannot read before-edit file"
        }
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
    let before_lines: Vec<&str> = before_content.lines().collect();
    let after_lines: Vec<&str> = after_content.lines().collect();
    let mut budget: HashMap<(&str, &str), usize> = HashMap::new();
    for v in before_violations {
        let Some(rule) = allowlist_entry(&v.rule) else {
            continue;
        };
        let Some(text) = v.line.and_then(|line| line_text(&before_lines, line)) else {
            continue;
        };
        *budget.entry((rule, text)).or_insert(0) += 1;
    }

    let mut kept = Vec::new();
    let mut demoted = Vec::new();
    for v in blocking {
        let preexisting = allowlist_entry(&v.rule).is_some_and(|rule| {
            v.line
                .and_then(|line| line_text(&after_lines, line))
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

fn line_text<'a>(lines: &[&'a str], line: u32) -> Option<&'a str> {
    let idx = (line as usize).checked_sub(1)?;
    lines.get(idx).map(|text| text.trim())
}

#[cfg(test)]
mod tests;
