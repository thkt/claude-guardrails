use super::{
    classify, demote_preexisting, demotion_eligible, read_failure_phrase, DEMOTABLE_RULES,
};
use crate::config::Config;
use crate::content::{BeforeSource, DegradedReason, ResolvedTarget};
use crate::hook::collect_violations;
use crate::rules::{Severity, Violation};
use std::collections::BTreeSet;
use std::fs;

fn violation(rule: &str, line: Option<u32>) -> Violation {
    Violation {
        rule: String::from(rule),
        severity: Severity::High,
        fix: String::new(),
        file: String::from("/src/app.ts"),
        line,
        origin: None,
    }
}

// T-283: a violation whose trimmed line text matches a before-edit violation
// demotes even when its line number and indentation changed.
#[test]
fn demotes_same_trimmed_text_at_different_line_and_indent() {
    let before_content = "const a = 1;\n  eval(userInput);\n";
    let after_content = "const a = 1;\nconst b = 2;\nconst c = 3;\n      eval(userInput);\n";
    let result = classify(
        vec![violation("eval", Some(4))],
        after_content,
        &[violation("eval", Some(2))],
        before_content,
    );
    assert_eq!(result.demoted.len(), 1);
    assert!(result.blocking.is_empty());
}

// T-278: demotion per identity is capped at the before-edit count, so a
// pasted extra copy of an existing violating line still blocks.
#[test]
fn caps_demotion_at_before_count_for_pasted_copy() {
    let before_content = "eval(userInput);\n";
    let after_content = "eval(userInput);\neval(userInput);\n";
    let result = classify(
        vec![violation("eval", Some(1)), violation("eval", Some(2))],
        after_content,
        &[violation("eval", Some(1))],
        before_content,
    );
    assert_eq!(result.demoted.len(), 1);
    assert_eq!(result.blocking.len(), 1);
}

// T-284: a violation reported without a line number never demotes; its
// per-line identity cannot be established.
#[test]
fn keeps_violation_without_line_number() {
    let content = "eval(userInput);\n";
    let result = classify(
        vec![violation("eval", None)],
        content,
        &[violation("eval", None)],
        content,
    );
    assert!(result.demoted.is_empty());
    assert_eq!(result.blocking.len(), 1);
}

// T-279: a rule outside the demotion allowlist keeps blocking even when the
// before-edit content carries the same violation with the same line text.
#[test]
fn keeps_non_allowlisted_rule_despite_matching_text() {
    let content = "db.insert(a); db.insert(b);\n";
    let result = classify(
        vec![violation("transaction-boundary", Some(1))],
        content,
        &[violation("transaction-boundary", Some(1))],
        content,
    );
    assert!(result.demoted.is_empty());
    assert_eq!(result.blocking.len(), 1);
}

// T-288: the second pass fires only when the toggle is on AND at least one
// blocking violation is on the demotion allowlist.
#[test]
fn second_pass_requires_toggle_and_allowlisted_blocking() {
    let allowlisted = [violation("eval", Some(1))];
    let foreign = [violation("transaction-boundary", Some(1))];
    assert!(!demotion_eligible(false, &allowlisted));
    assert!(!demotion_eligible(true, &[]));
    assert!(!demotion_eligible(true, &foreign));
    assert!(demotion_eligible(true, &allowlisted));
}

// T-293: each before-edit read failure resolves to its own skip-note phrase,
// so the note names the actual failure instead of one catch-all wording.
#[test]
fn read_failure_phrases_are_distinct_per_reason() {
    let phrases = [
        read_failure_phrase(DegradedReason::OversizedFile),
        read_failure_phrase(DegradedReason::NonUtf8Content),
        read_failure_phrase(DegradedReason::FileNotFound),
        read_failure_phrase(DegradedReason::PermissionDenied),
        read_failure_phrase(DegradedReason::IoError),
        read_failure_phrase(DegradedReason::PathOutsideProject),
    ];
    let distinct: BTreeSet<&str> = phrases.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        phrases.len(),
        "each read-failure reason needs its own phrase"
    );
}

// T-296: with the project root unresolved, the path-boundary check cannot
// run, so the on-disk before read must not happen at all; otherwise a file
// outside the (unknown) project could drive demotion. Everything keeps
// blocking and the skip note says the boundary cannot be verified.
#[test]
fn keeps_all_when_project_root_is_unresolved() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("app.ts");
    fs::write(&path, "eval(userInput);\n").unwrap();

    let config = Config {
        diff_aware: true,
        ..Config::default()
    };
    let target = ResolvedTarget {
        file_path: path.to_string_lossy().into_owned(),
        content: String::from("eval(userInput);\nconst a = 1;\n"),
        is_js: true,
        degraded: None,
        before: BeforeSource::OnDisk,
    };

    let outcome = demote_preexisting(vec![violation("eval", Some(1))], target, &config, None);

    assert_eq!(outcome.blocking.len(), 1, "must keep blocking, not demote");
    assert!(outcome.demoted.is_empty());
    let note = outcome.skip_note.expect("skip note must explain the skip");
    assert!(
        note.contains("cannot verify before-edit file is inside the project"),
        "got: {note}"
    );
    assert!(outcome.info_note.is_none());
}

// T-287: every allowlisted rule reports each occurrence on its own line (two
// same-rule violations, two distinct lines), so demotion budgets stay
// accurate. The trailing set assert forces a table entry per enrolled rule.
#[test]
fn allowlisted_rules_report_every_occurrence() {
    const TWO_OCCURRENCE_FIRES: &[(&str, &str, &str)] =
        &[("eval", "/src/app.ts", "eval(alpha);\neval(beta);\n")];

    let mut config = Config::default();
    config.rules.oxlint = false;

    for (rule, path, content) in TWO_OCCURRENCE_FIRES {
        let (violations, notes) = collect_violations(path, content, &config, None, true);
        assert!(notes.is_empty(), "{rule}: notes must be empty: {notes:?}");
        let lines: Vec<u32> = violations
            .iter()
            .filter(|v| v.rule == *rule)
            .filter_map(|v| v.line)
            .collect();
        assert_eq!(lines.len(), 2, "{rule}: both occurrences must carry a line");
        let distinct: BTreeSet<u32> = lines.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            2,
            "{rule}: occurrences must sit on distinct lines"
        );
    }

    let table: BTreeSet<&str> = TWO_OCCURRENCE_FIRES.iter().map(|(r, _, _)| *r).collect();
    let allowlist: BTreeSet<&str> = DEMOTABLE_RULES.iter().copied().collect();
    assert_eq!(
        table, allowlist,
        "every allowlisted rule needs a two-occurrence pin entry"
    );
}
