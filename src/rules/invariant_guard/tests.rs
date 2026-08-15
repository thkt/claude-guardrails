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

// T-584: the spelling holds no `..`, so only symlink resolution can turn
// `sub/alias/` back into the root and reach the declaration file under it.
#[test]
fn symlink_経由で綴った_invariants_json_でも判定される() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    fs::write(
        root.join(INVARIANTS_FILE),
        r#"{"config.json": {"featureFlag": true}}"#,
    )
    .unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    std::os::unix::fs::symlink(&root, root.join("sub").join("alias")).unwrap();
    let spelled = root.join("sub").join("alias").join(INVARIANTS_FILE);

    let v = check(spelled.to_str().unwrap(), "{}", Some(&root));

    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].severity, Severity::Critical);
    assert_eq!(v[0].rule, rule_id::INVARIANT_GUARD);
}

// T-595: the edited path resolves out of the repository, yet the disk read
// follows the same symlink, so the pins are still enforced.
#[test]
fn 根の_invariants_json_が_repository_外への_symlink_でも判定される() {
    let tmp = tempfile::TempDir::new().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let root = base.join("repo");
    let outside = base.join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    let target = outside.join("pins.json");
    fs::write(&target, r#"{"config.json": {"featureFlag": true}}"#).unwrap();
    std::os::unix::fs::symlink(&target, root.join(INVARIANTS_FILE)).unwrap();

    let v = check(
        root.join(INVARIANTS_FILE).to_str().unwrap(),
        "{}",
        Some(&root),
    );

    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].severity, Severity::Critical);
    assert_eq!(v[0].rule, rule_id::INVARIANT_GUARD);
}

// T-596: `missing/..` climbs back to the root, but the directory it climbs out
// of does not exist yet at PreToolUse, so nothing on disk resolves it. Folding
// `..` lexically is what keeps this spelling from slipping past the guard.
#[test]
fn 存在しないディレクトリを経由して綴った_invariants_json_でも判定される() {
    let tmp = root_with_invariants(r#"{"config.json": {"featureFlag": true}}"#);
    let spelled = tmp.path().join("missing").join("..").join(INVARIANTS_FILE);

    let v = check(spelled.to_str().unwrap(), "{}", Some(tmp.path()));

    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].rule, rule_id::INVARIANT_GUARD);
}

// T-591: a declaration file whose post-edit content never arrives is judged by
// nothing, so the skip is reported instead of passing silently.
#[test]
fn 再構成できない宣言ファイルの編集は_note_で報告される() {
    let tmp = root_with_invariants(r#"{"config.json": {"featureFlag": true}}"#);
    let path = tmp.path().join(INVARIANTS_FILE);

    let note = degraded_note(path.to_str().unwrap(), Some(tmp.path()));

    assert!(
        note.as_deref().is_some_and(|n| n.contains(INVARIANTS_FILE)),
        "{note:?}"
    );
}

// T-592: any other file is out of this guard's scope, so a degraded read of it
// must not add a note about pins.
#[test]
fn 宣言ファイル以外の再構成失敗では_note_が出ない() {
    let tmp = root_with_invariants(r#"{"config.json": {"featureFlag": true}}"#);
    let path = tmp.path().join("config.json");

    assert!(degraded_note(path.to_str().unwrap(), Some(tmp.path())).is_none());
}
