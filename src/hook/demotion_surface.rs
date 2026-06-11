//! Demotion-surface measurement harness (test-only).
//!
//! Drives the production classifier with before/after fixture pairs per
//! enrolled rule and scenario, asserting the exact (demoted, blocking) split.
//! Fixture bodies live under `demotion_surface/fixtures/` as `.txt` files so
//! editing them does not trigger this repo's own `PreToolUse` hook; a missing
//! fixture is a build error, not a silent corpus hole.
//!
//! The bypass assertion is absolute: a violation demoted without a matching
//! (rule, trimmed line text) occurrence in the before content fails the test.
//! No threshold, no snapshot.

mod corpus;

use std::collections::{BTreeSet, HashMap};

use super::diff_aware::{classify, DEMOTABLE_RULES};
use super::{collect_first_party_violations, partition_violations};
use crate::config::Config;
use crate::rules::{Violation, RE_JS_FILE};

/// The three scenarios every enrolled rule must cover: `preserved` (the
/// before violation survives the edit and demotes), `added` (a violation new
/// in after blocks next to a demoted one), `surplus-copy` (a pasted extra
/// copy of the same line exceeds the before count and blocks).
const SCENARIOS: &[&str] = &["preserved", "added", "surplus-copy"];

/// One before/after fixture pair pinned to the enrolled rule and scenario it
/// measures, with the exact classification split the pair must produce.
struct PairSample {
    rule: &'static str,
    scenario: &'static str,
    path: &'static str,
    before: &'static str,
    after: &'static str,
    expected_demoted: usize,
    expected_blocking: usize,
}

/// Production default with oxlint delegation off: pairs cover first-party
/// rules only and must not depend on an oxlint binary.
fn harness_config() -> Config {
    let mut config = Config::default();
    config.rules.oxlint = false;
    config
}

/// First-party lint mirroring the production before-pass. Notes fail loudly:
/// with oxlint off the only possible note is an AST parse failure, which
/// would mean the fixture no longer exercises the classifier.
fn first_party_violations(path: &str, content: &str, config: &Config) -> Vec<Violation> {
    let (violations, notes) =
        collect_first_party_violations(path, content, config, RE_JS_FILE.is_match(path));
    assert!(
        notes.is_empty(),
        "pipeline notes for {path}: {notes:?} (fixture no longer parses?)"
    );
    violations
}

/// Line resolution reimplemented independently from the classifier so the
/// bypass assertion does not share a bug with the code under test.
fn trimmed_line(content: &str, line: u32) -> Option<&str> {
    let idx = (line as usize).checked_sub(1)?;
    content.lines().nth(idx).map(str::trim)
}

/// Multiset of (rule, trimmed line text) occurrences for bypass accounting.
fn count_by_rule_and_text<'a>(
    violations: &'a [Violation],
    content: &'a str,
) -> HashMap<(&'a str, &'a str), usize> {
    let mut counts = HashMap::new();
    for v in violations {
        if let Some(text) = v.line.and_then(|line| trimmed_line(content, line)) {
            *counts.entry((v.rule.as_str(), text)).or_insert(0) += 1;
        }
    }
    counts
}

// T-291: 各 pair を first-party lint → partition → classify に通し、(降格数, block 数)
// が expected と一致する。before に無い違反の降格 (bypass) は閾値なしの絶対 0。
#[test]
fn corpus_pairs_classify_to_expected_counts_with_zero_bypass() {
    let config = harness_config();
    for pair in corpus::PAIRS {
        let label = format!("{} / {}", pair.rule, pair.scenario);
        let before_violations = first_party_violations(pair.path, pair.before, &config);
        let after_violations = first_party_violations(pair.path, pair.after, &config);
        let (blocking, _) = partition_violations(after_violations, &config);
        let result = classify(blocking, pair.after, &before_violations, pair.before);

        assert_eq!(
            (result.demoted.len(), result.blocking.len()),
            (pair.expected_demoted, pair.expected_blocking),
            "unexpected (demoted, blocking) split for {label}"
        );

        for v in &result.demoted {
            assert!(
                v.line
                    .and_then(|line| trimmed_line(pair.after, line))
                    .is_some(),
                "BYPASS in {label}: demoted {} violation has no resolvable line",
                v.rule
            );
        }
        let demoted_counts = count_by_rule_and_text(&result.demoted, pair.after);
        let before_counts = count_by_rule_and_text(&before_violations, pair.before);
        for ((rule, text), demoted) in &demoted_counts {
            let available = before_counts.get(&(*rule, *text)).copied().unwrap_or(0);
            assert!(
                *demoted <= available,
                "BYPASS in {label}: ({rule}, {text:?}) demoted {demoted} times but before had {available}"
            );
        }
    }
}

// T-292: locality allowlist と corpus manifest の rule 集合が一致し、enrolled rule
// ごとに 3 シナリオ全ての pair が揃う (allowlist 追加時に corpus pair 追加を強制)。
#[test]
fn corpus_rules_match_allowlist_with_every_scenario() {
    let corpus_rules: BTreeSet<&str> = corpus::PAIRS.iter().map(|p| p.rule).collect();
    let allowlist: BTreeSet<&str> = DEMOTABLE_RULES.iter().copied().collect();
    assert_eq!(
        corpus_rules, allowlist,
        "corpus manifest rule set must equal DEMOTABLE_RULES"
    );
    for pair in corpus::PAIRS {
        assert!(
            SCENARIOS.contains(&pair.scenario),
            "unknown scenario {} on rule {}",
            pair.scenario,
            pair.rule
        );
    }
    for rule in DEMOTABLE_RULES {
        for scenario in SCENARIOS {
            assert!(
                corpus::PAIRS
                    .iter()
                    .any(|p| p.rule == *rule && p.scenario == *scenario),
                "rule {rule} has no {scenario} pair"
            );
        }
    }
}
