use super::*;
use std::fs;

/// Writes a `.invariants.json` with `pins_json` as its pre-edit content and
/// returns the owning tempdir (the git root for `check`).
fn root_with_invariants(pins_json: &str) -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::write(tmp.path().join(".invariants.json"), pins_json).unwrap();
    tmp
}

// T-582: pin を消す編集が Critical の violation になる
#[test]
fn pin_を消す編集が_critical_の_violation_になる() {
    let tmp = root_with_invariants(r#"{"config.json": {"featureFlag": true}}"#);
    let path = tmp.path().join(".invariants.json");

    let v = check(path.to_str().unwrap(), "{}", Some(tmp.path()));

    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].severity, Severity::Critical);
    assert_eq!(v[0].rule, rule_id::INVARIANT_GUARD);
}

// T-583: pin を足す編集では violation が出ない
#[test]
fn pin_を足す編集では_violation_が出ない() {
    let tmp = root_with_invariants(r#"{"config.json": {"featureFlag": true}}"#);
    let path = tmp.path().join(".invariants.json");
    let post_edit =
        r#"{"config.json": {"featureFlag": true}, "other.json": {"apiBase": "https://x"}}"#;

    let v = check(path.to_str().unwrap(), post_edit, Some(tmp.path()));

    assert!(v.is_empty(), "{v:?}");
}

// T-584: symlink 経由で綴った `.invariants.json` でも判定される
#[test]
fn symlink_経由で綴った_invariants_json_でも判定される() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    fs::write(
        root.join(".invariants.json"),
        r#"{"config.json": {"featureFlag": true}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&root, root.join("link")).unwrap();
    // `link` は root 自身を指すので、綴りを畳むと root 直下の `.invariants.json` になる。
    let spelled = root.join("link").join("..").join(".invariants.json");

    let v = check(spelled.to_str().unwrap(), "{}", Some(&root));

    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].severity, Severity::Critical);
    assert_eq!(v[0].rule, rule_id::INVARIANT_GUARD);
}
