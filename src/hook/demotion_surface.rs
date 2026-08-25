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

use super::diff_aware::{classify, Classification, DEMOTABLE_RULES};
use super::{collect_first_party_violations, partition_violations};
use crate::config::Config;
use crate::rules::{Violation, RE_JS_FILE};

/// The scenarios every enrolled rule must cover: `preserved` (the before
/// violation survives the edit and demotes), `added` (a violation new in after
/// blocks next to a demoted one), `surplus-copy` (a pasted extra copy of the
/// same line exceeds the before count and blocks), `swap` (the before
/// violation line is removed and an identical-text violation is added
/// elsewhere; the (rule, trimmed text) multiset is unchanged so it demotes,
/// pinning that identity is position-independent), `replaced` (the before
/// violation line is removed and a different-text violation takes its place;
/// the after key is absent from the before multiset so it cannot borrow the
/// deleted line's demotion budget and blocks, pinning that a delete+add of
/// different text is not a free pass), `payload-swap` (the reported line's
/// text stays byte-identical between before and after; only a different line
/// that feeds that report — raw-html's array literal, eval's import alias —
/// changes. Identity is keyed on report-line text alone, so a rule that is
/// still demotable would see no change at all; raw-html's opted-out bind+join
/// violation keeps blocking regardless, and eval's alias change makes the
/// call line stop being a violation in `after` in the first place, so there
/// is nothing left to demote).
//
// The demotion budget is keyed on trimmed line text, so enrollment assumes
// text identity equals violation identity for a rule: the same line means the
// same severity wherever it sits. eval (a flat substring match) satisfies that,
// as do raw-html's single-line branches (concat / template / inline-join).
// raw-html's bind+join branch is context-dependent (a join line violates only
// near an HTML-array bind that sits on a different line), so its violation
// identity is not fully determined by the trimmed `.join()` line alone; it
// fails the ADR-0020 amendment's locality test and sets `no_demote` on push
// (`rules::raw_html::make_violation_with_opt_out`), which always blocks
// regardless of before/after content. The raw-html swap fixture uses the join
// form and pins that opt-out. A future context-dependent rule needs the same
// opt-out, plus before/after pinning, before it joins DEMOTABLE_RULES.
const SCENARIOS: &[&str] = &[
    "preserved",
    "added",
    "surplus-copy",
    "swap",
    "replaced",
    "payload-swap",
];

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

/// Looks up the one `payload-swap` pair for `rule`, run through the same
/// first_party_violations -> partition_violations -> classify pipeline as the
/// exhaustive sweep, so a T-NNN test failure and the sweep test's failure
/// share one root cause instead of drifting apart.
fn classify_payload_swap_pair(rule: &'static str) -> Classification {
    let config = harness_config();
    let pair = corpus::PAIRS
        .iter()
        .find(|p| p.rule == rule && p.scenario == "payload-swap")
        .unwrap_or_else(|| panic!("no payload-swap pair for rule {rule}"));
    let before_violations = first_party_violations(pair.path, pair.before, &config);
    let after_violations = first_party_violations(pair.path, pair.after, &config);
    let (blocking, _) = partition_violations(after_violations, &config);
    classify(blocking, pair.after, &before_violations, pair.before)
}

// T-625: raw-html's bind+join violation carries the demotion opt-out
// (U-002), and `classify` always keeps an opted-out violation blocking
// (U-001) regardless of a before/after line-text match. This pins that the
// two wire together end to end: even with the `.join()` report line held
// byte-identical, changing the HTML array literal's contents (the payload)
// still blocks rather than demoting, because the opt-out — not a text
// mismatch — is what keeps it blocking.
#[test]
fn with_the_join_line_byte_identical_changing_the_html_array_literals_contents_demotes_nothing_and_blocks_one_raw_html_violation(
) {
    let result = classify_payload_swap_pair("raw-html");
    assert_eq!(result.demoted.len(), 0, "expected nothing demoted");
    assert_eq!(
        result.blocking.len(),
        1,
        "expected exactly one blocked violation"
    );
    assert_eq!(result.blocking[0].rule, "raw-html");
}

// T-626: eval resolves its target through the import alias's original name,
// so renaming the alias away from `eval` (the payload) stops the call line
// from being a violation in `after` at all, even though the call line's text
// is byte-identical to `before`. With nothing blocking on the after side,
// `classify` has nothing to demote and nothing to keep.
#[test]
fn with_the_call_line_byte_identical_changing_the_import_alias_away_from_eval_demotes_nothing_and_blocks_nothing(
) {
    let result = classify_payload_swap_pair("eval");
    assert_eq!(result.demoted.len(), 0, "expected nothing demoted");
    assert_eq!(result.blocking.len(), 0, "expected nothing blocked");
}
