use super::{classify, demotion_eligible, DEMOTABLE_RULES};
use crate::config::Config;
use crate::hook::collect_violations;
use crate::rules::{Severity, Violation};
use std::collections::BTreeSet;

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
