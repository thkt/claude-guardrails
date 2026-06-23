//! Unit tests for the semantic invariant gate (#359).
//!
//! Each test references its T-NNN id from spec.md Test Scenarios (T-1..T-21).
//!
//! Red-phase note: the functions under test are no-op stubs returning an empty
//! `Vec`, so scenarios that expect >=1 violation are genuinely Red (fail now),
//! while scenarios whose spec expectation is 0 violations pass against the stub
//! and only discriminate once the gate is implemented. Both are encoded
//! faithfully to the spec rather than distorted to force a failure.

use super::*;
use crate::rules::{rule_id, Severity};
use serde_json::json;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

/// Builds a `serde_json::Map` pin table from a JSON object literal, consuming
/// the value so no clone is needed.
fn pin_table(value: serde_json::Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("pin table must be a JSON object"),
    }
}

/// Counts violations carrying the invariant rule id.
fn invariant_count(violations: &[Violation]) -> usize {
    violations
        .iter()
        .filter(|v| v.rule == rule_id::INVARIANT)
        .count()
}

/// Writes a `.invariants.json` into `git_root` and returns the absolute file
/// path for `rel` under that root.
fn setup_invariants(git_root: &Path, invariants_json: &str, rel: &str) -> String {
    fs::write(git_root.join(".invariants.json"), invariants_json).expect("write .invariants.json");
    git_root.join(rel).to_string_lossy().into_owned()
}

// --- run_invariant_pass disk-backed scenarios ------------------------------

// T-1: flipping a pinned flag (declared false, edited true) yields exactly one
// High invariant violation.
#[test]
fn flips_flag_value_produces_violation() {
    let tmp = TempDir::new().unwrap();
    let rel = "src/config/flags.json";
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
        rel,
    );
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 1);
    assert!(violations
        .iter()
        .all(|v| v.severity == Severity::High || v.rule != rule_id::INVARIANT));
}

// T-2: declared false and edited false agree, so no violation fires.
#[test]
fn matching_flag_value_produces_no_violation() {
    let tmp = TempDir::new().unwrap();
    let rel = "src/config/flags.json";
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
        rel,
    );
    let post_edit = r#"{ "checkout": { "v2": false } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 0);
}

// T-9: a missing `.invariants.json` skips the gate (fail-open) with no
// violation. (git_root has no .invariants.json written.)
#[test]
fn absent_invariants_file_skips_with_no_violation() {
    let tmp = TempDir::new().unwrap();
    let abs = tmp
        .path()
        .join("src/config/flags.json")
        .to_string_lossy()
        .into_owned();
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 0);
}

// T-10: a malformed `.invariants.json` fails closed with exactly one violation.
#[test]
fn corrupt_invariants_file_fails_closed_with_violation() {
    let tmp = TempDir::new().unwrap();
    let rel = "src/config/flags.json";
    let abs = setup_invariants(tmp.path(), "{ this is not valid json", rel);
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 1);
}

// T-13: a multi-segment absolute file_path is stripped to its git_root-relative
// key and matched against the declaration keyed by that same relative path.
// Distinct from T-1: a deeper directory (locales/nested/en.json) and a string
// pin exercise the strip over several path segments. Encoded as a mismatch so
// the firing violation proves the strip + lookup ran (FR8/AC7).
#[test]
fn strips_multi_segment_git_root_prefix_then_matches_declaration() {
    let tmp = TempDir::new().unwrap();
    let rel = "locales/nested/en.json";
    fs::create_dir_all(tmp.path().join("locales/nested")).unwrap();
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "locales/nested/en.json": { "legal.terms": "Original terms." } }"#,
        rel,
    );
    let post_edit = r#"{ "legal": { "terms": "Edited terms." } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 1);
}

// T-14: an absolute file_path outside git_root cannot be stripped, so the gate
// skips with no violation.
#[test]
fn file_outside_git_root_is_skipped() {
    let tmp = TempDir::new().unwrap();
    setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
        "src/config/flags.json",
    );
    let abs = "/elsewhere/src/config/flags.json";
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 0);
}

// T-12: a file_path absent from the declaration table skips with no violation.
#[test]
fn undeclared_file_path_is_skipped() {
    let tmp = TempDir::new().unwrap();
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
        "locales/en.json",
    );
    let post_edit = r#"{ "legal": { "terms": "x" } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 0);
}

// T-15: a Write tool supplies the full JSON as structured_full; a mismatched
// value yields one invariant violation. (The "Write supplies full content"
// wiring itself is T-16's content-layer concern; here the full content is fed
// directly to run_invariant_pass.)
#[test]
fn full_content_with_mismatch_produces_violation() {
    let tmp = TempDir::new().unwrap();
    let rel = "src/config/flags.json";
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": { "ui.maxItems": 50 } }"#,
        rel,
    );
    let post_edit = r#"{ "ui": { "maxItems": 999 } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 1);
}

// run_invariant_pass guard order: structured_full None and git_root None.

// T-15 guard: structured_full None (non-.json or failed reconstruction) skips
// before any disk read.
#[test]
fn none_structured_full_skips_pass() {
    let tmp = TempDir::new().unwrap();
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
        "src/config/flags.json",
    );

    let violations = run_invariant_pass(&abs, None, Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 0);
}

// T-14 guard: a None git_root skips the pass (no anchor to read .invariants.json).
#[test]
fn none_git_root_skips_pass() {
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass("/repo/src/config/flags.json", Some(post_edit), None);

    assert_eq!(invariant_count(&violations), 0);
}

// --- check_invariants pure-logic scenarios ---------------------------------

// T-3: a number pin (declared 50) mismatched by an edit to 51 yields one
// violation.
#[test]
fn number_pin_off_by_one_produces_violation() {
    let declared = pin_table(json!({ "ui.maxItems": 50 }));
    let content = r#"{ "ui": { "maxItems": 51 } }"#;

    let violations = check_invariants(&declared, content, "src/config/flags.json");

    assert_eq!(invariant_count(&violations), 1);
}

// T-4: a string pin whose edited value matches yields no violation.
#[test]
fn matching_string_pin_produces_no_violation() {
    let declared = pin_table(json!({ "legal.terms": "By continuing you agree." }));
    let content = r#"{ "legal": { "terms": "By continuing you agree." } }"#;

    let violations = check_invariants(&declared, content, "locales/en.json");

    assert_eq!(invariant_count(&violations), 0);
}

// T-5: a bool pin (true) against a string "true" is a type mismatch under
// serde_json::Value equality, so one violation fires.
#[test]
fn bool_pin_against_string_value_is_type_mismatch() {
    let declared = pin_table(json!({ "checkout.v2": true }));
    let content = r#"{ "checkout": { "v2": "true" } }"#;

    let violations = check_invariants(&declared, content, "src/config/flags.json");

    assert_eq!(invariant_count(&violations), 1);
}

// T-6: a pinned path removed from the content is unresolved, yielding one
// violation (deletion/rename detection).
#[test]
fn removed_pin_path_is_unresolved_violation() {
    let declared = pin_table(json!({ "checkout.v2": false }));
    let content = r#"{ "ui": { "maxItems": 50 } }"#;

    let violations = check_invariants(&declared, content, "src/config/flags.json");

    assert_eq!(invariant_count(&violations), 1);
}

// T-7: a flat literal key `{"legal.terms": ...}` resolves the `legal.terms`
// pin (flat preferred); when it matches there is no violation.
#[test]
fn flat_key_resolves_dot_path_no_violation_on_match() {
    let declared = pin_table(json!({ "legal.terms": "Terms apply." }));
    let content = r#"{ "legal.terms": "Terms apply." }"#;

    let violations = check_invariants(&declared, content, "locales/en.json");

    assert_eq!(invariant_count(&violations), 0);
}

// T-8: a nested object `{"legal": {"terms": ...}}` resolves the `legal.terms`
// pin via nested fallback. Encoded as a mismatch so the firing violation
// proves nested descent ran.
#[test]
fn nested_object_resolves_dot_path_via_fallback() {
    let declared = pin_table(json!({ "legal.terms": "Original terms." }));
    let content = r#"{ "legal": { "terms": "Tampered terms." } }"#;

    let violations = check_invariants(&declared, content, "locales/en.json");

    assert_eq!(invariant_count(&violations), 1);
}

// T-20: a flat key `{"a.b": X}` and nested `{"a": {"b": Y}}` coexist; the
// `a.b` pin resolves flat value X (nested Y ignored). With declared == X there
// is no violation.
//
// Decision table (resolution precedence for dot_path "a.b"):
// | flat "a.b" present | nested a.b present | resolved value |
// | ------------------ | ------------------ | -------------- |
// | yes                | yes                | flat (X)       |  <- this test
// | no                 | yes                | nested (Y)     |  <- T-8
// | yes                | no                 | flat (X)       |  <- T-7
// | no                 | no                 | unresolved     |  <- T-6
#[test]
fn flat_key_wins_over_nested_on_collision() {
    let declared = pin_table(json!({ "a.b": "X" }));
    let content = r#"{ "a.b": "X", "a": { "b": "Y" } }"#;

    let violations = check_invariants(&declared, content, "src/config/data.json");

    assert_eq!(invariant_count(&violations), 0);
}

// T-17: a declared value that is an object (non-scalar) is a config error,
// yielding one violation. (AC9)
#[test]
fn object_declared_value_is_config_error() {
    let declared = pin_table(json!({ "checkout": { "v2": false } }));
    let content = r#"{ "checkout": { "v2": false } }"#;

    let violations = check_invariants(&declared, content, "src/config/flags.json");

    assert_eq!(invariant_count(&violations), 1);
}

// T-18: a null pin matched by an edited null yields no violation; an edited
// non-null yields one. Both cases asserted.
#[test]
fn null_pin_matches_null_but_rejects_non_null() {
    let declared = pin_table(json!({ "feature.beta": null }));

    let matching = check_invariants(&declared, r#"{ "feature": { "beta": null } }"#, "f.json");
    assert_eq!(invariant_count(&matching), 0);

    let drifted = check_invariants(&declared, r#"{ "feature": { "beta": 1 } }"#, "f.json");
    assert_eq!(invariant_count(&drifted), 1);
}

// T-19: post-edit content that is not parseable JSON fails closed with one
// violation (a tamper could have broken it).
#[test]
fn unparseable_content_fails_closed_with_violation() {
    let declared = pin_table(json!({ "checkout.v2": false }));
    let content = "{ broken json :::";

    let violations = check_invariants(&declared, content, "src/config/flags.json");

    assert_eq!(invariant_count(&violations), 1);
}

// T-21: serde_json::Value number equality is representation-strict — an int and
// a float of the same magnitude are not equal, so a pin declared int 50 vs
// edited float 50.0 mismatches in BOTH directions, each firing one violation.
// (Empirically confirmed by this test run; serde_json stores integer and float
// numbers in distinct internal variants.)
#[test]
fn int_pin_vs_float_value_is_mismatch_both_directions() {
    // declared int 50, edited float 50.0
    let declared_int = pin_table(json!({ "ui.maxItems": 50 }));
    let edited_float = r#"{ "ui": { "maxItems": 50.0 } }"#;
    let v1 = check_invariants(&declared_int, edited_float, "src/config/flags.json");
    assert_eq!(invariant_count(&v1), 1);

    // declared float 50.0, edited int 50
    let declared_float = pin_table(json!({ "ui.maxItems": 50.0 }));
    let edited_int = r#"{ "ui": { "maxItems": 50 } }"#;
    let v2 = check_invariants(&declared_float, edited_int, "src/config/flags.json");
    assert_eq!(invariant_count(&v2), 1);
}

// T-21 (semantics pin): records the raw serde_json::Value equality fact this
// gate relies on, independent of the gate impl. If serde_json ever makes
// cross-representation numbers equal, this fails and the int/float test above
// must be revisited.
#[test]
fn serde_json_number_equality_is_representation_strict() {
    assert_ne!(json!(50), json!(50.0));
    assert_eq!(json!(50), json!(50));
    assert_ne!(json!(true), json!("true"));
}

// --- fail-open / key-resolution remediation scenarios ----------------------

// T-23: an empty `.invariants.json` declares no pins, so editing any `.json`
// (here an undeclared one) must fail open with zero violations rather than
// treat the empty file as corrupt and block every `.json` edit repo-wide. The
// whitespace-only variant is asserted the same way.
#[test]
fn empty_or_whitespace_invariants_file_fails_open_no_violation() {
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    for body in ["", "   \n\t  "] {
        let tmp = TempDir::new().unwrap();
        let abs = setup_invariants(tmp.path(), body, "src/config/flags.json");
        let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));
        assert_eq!(
            invariant_count(&violations),
            0,
            "empty/whitespace pin file must not block (body {body:?})"
        );
    }
}

// T-24: a valid `.invariants.json` carrying a leading UTF-8 BOM must parse after
// BOM stripping and still enforce its pin; a mismatched edit fires one
// violation. The BOM must not be mistaken for corruption and fail closed.
#[test]
fn bom_prefixed_invariants_file_parses_and_enforces_pin() {
    let tmp = TempDir::new().unwrap();
    let abs = setup_invariants(
        tmp.path(),
        "\u{feff}{ \"src/config/flags.json\": { \"checkout.v2\": false } }",
        "src/config/flags.json",
    );
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 1);
    // Discriminate the fix: the violation must be the pin-drift report for the
    // declared path, not a fail-closed "not a valid JSON object" message (which
    // the pre-fix code would have produced by treating the BOM as corruption).
    assert!(
        violations[0].fix.contains("checkout.v2") && violations[0].fix.contains("changed to"),
        "expected pin-drift violation, got: {}",
        violations[0].fix
    );
}

// T-25: when the file_path reaches the gate through a symlinked ancestor while
// the declaration key is the canonical relative path, the pin must still be
// enforced. The raw symlink path does not start with the canonical git root, so
// only canonical key resolution makes the lookup match.
#[test]
fn symlinked_ancestor_path_resolves_to_canonical_pin_key() {
    let tmp = TempDir::new().unwrap();
    let real_root = fs::canonicalize(tmp.path()).unwrap();
    let config_dir = real_root.join("src/config");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("flags.json"), "{}").unwrap();
    fs::write(
        real_root.join(".invariants.json"),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();

    let link_root = real_root.join("link");
    symlink(&real_root, &link_root).unwrap();
    let symlinked_path = link_root.join("src/config/flags.json");
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(
        &symlinked_path.to_string_lossy(),
        Some(post_edit),
        Some(&real_root),
    );

    assert_eq!(
        invariant_count(&violations),
        1,
        "pin must enforce through a symlinked ancestor path"
    );
}

// T-26: the structured-config predicate matches the `.json` extension
// case-insensitively, so an uppercase `.JSON` target is recognized.
#[test]
fn uppercase_json_extension_is_structured_config() {
    assert!(is_structured_config("src/config/flags.JSON"));
    assert!(is_structured_config("src/config/flags.Json"));
    assert!(!is_structured_config("src/config/flags.yaml"));
}

// T-27: a degraded post-edit reconstruction for a pinned file surfaces a note so
// the unverified pin is visible; a degraded reconstruction for an unpinned file
// stays silent (no note), avoiding noise where there is nothing to verify.
#[test]
fn degraded_note_surfaces_only_for_pinned_file() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join(".invariants.json"),
        r#"{ "src/config/flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();

    let pinned = tmp.path().join("src/config/flags.json");
    let pinned_note = degraded_note(&pinned.to_string_lossy(), Some(tmp.path()));
    assert!(
        pinned_note.is_some(),
        "pinned file must surface a degraded note"
    );

    let unpinned = tmp.path().join("src/config/other.json");
    let unpinned_note = degraded_note(&unpinned.to_string_lossy(), Some(tmp.path()));
    assert!(
        unpinned_note.is_none(),
        "unpinned file must stay silent on degraded reconstruction"
    );
}

// T-28: a corrupt `.invariants.json` co-occurring with a degraded post-edit read
// must not vanish silently. The corrupt-pin fail-closed path in the value pass is
// gated on reconstructed content, which a degraded read lacks, so `degraded_note`
// carries the corrupt-pin signal instead of returning `None`.
#[test]
fn degraded_note_surfaces_corrupt_pin_file() {
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join(".invariants.json"), "{ not valid json").unwrap();

    let any_json = tmp.path().join("src/config/flags.json");
    let note = degraded_note(&any_json.to_string_lossy(), Some(tmp.path()));
    assert!(
        note.is_some_and(|n| n.contains("not a valid JSON object")),
        "corrupt pin file must surface a note even when the edited file is degraded"
    );
}

// T-30: an absent `.invariants.json` (nothing pinned anywhere) means a degraded
// post-edit read has nothing to verify, so `degraded_note` stays silent (None)
// rather than reporting a skip for an unpinned repo.
#[test]
fn degraded_note_absent_pin_file_is_silent() {
    let tmp = TempDir::new().unwrap();
    let any_json = tmp.path().join("src/config/flags.json");

    let note = degraded_note(&any_json.to_string_lossy(), Some(tmp.path()));

    assert!(
        note.is_none(),
        "absent .invariants.json must not surface a degraded note"
    );
}

// T-31: a `.invariants.json` entry whose value is a scalar (not an object of
// pinned-path -> scalar) is a config error, yielding one violation. Distinct from
// T-17, which rejects a non-scalar pinned *value* inside a well-formed entry;
// here the per-file entry itself is malformed.
#[test]
fn scalar_file_entry_is_config_error() {
    let tmp = TempDir::new().unwrap();
    let rel = "src/config/flags.json";
    let abs = setup_invariants(
        tmp.path(),
        r#"{ "src/config/flags.json": "not an object" }"#,
        rel,
    );
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(tmp.path()));

    assert_eq!(invariant_count(&violations), 1);
    assert!(
        violations[0].fix.contains("must be an object"),
        "expected malformed-entry config error, got: {}",
        violations[0].fix
    );
}

// T-32: a file whose parent directory exists but lies outside git_root canonicalizes
// successfully (unlike T-14's non-existent `/elsewhere` parent), so key resolution
// reaches the canonical pair, its strip_prefix fails, and the raw-path fallback also
// fails. The pin lookup misses and the gate fails open with no violation.
#[test]
fn file_with_resolvable_parent_outside_root_is_skipped() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("repo");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        root.join(".invariants.json"),
        r#"{ "flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();
    let abs = outside.join("flags.json").to_string_lossy().into_owned();
    let post_edit = r#"{ "checkout": { "v2": true } }"#;

    let violations = run_invariant_pass(&abs, Some(post_edit), Some(&root));

    assert_eq!(invariant_count(&violations), 0);
}
