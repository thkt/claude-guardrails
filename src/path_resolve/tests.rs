use super::*;
use std::fs;

fn tmp_root() -> tempfile::TempDir {
    tempfile::TempDir::new().unwrap()
}

/// macOS の tempdir は `/var -> /private/var` の下にあり、`current_dir` 由来の
/// git root と同じ空間に揃えるには実体パスが要る。テストの root は production の
/// `find_git_root(env::current_dir())` が返す形 (symlink 解決済み) に合わせる。
fn real_root(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    tmp.path().canonicalize().unwrap()
}

// T-469: symlink のディレクトリを含む file_path は symlink 先の root 相対パスに解決される
#[test]
fn symlink_のディレクトリを含む_file_path_は_symlink_先の_root_相対パスに解決される() {
    let tmp = tmp_root();
    let root = real_root(&tmp);
    fs::create_dir_all(root.join("src/allowed")).unwrap();
    fs::create_dir_all(root.join("src/protected")).unwrap();
    std::os::unix::fs::symlink("../protected", root.join("src/allowed/esc")).unwrap();

    let resolved = resolve_under_root(&root.join("src/allowed/esc/app.ts"), &root).unwrap();

    assert_eq!(resolved.relative, Path::new("src/protected/app.ts"));
    assert!(resolved.moved);
}

// T-470: symlink になっているファイル自体を指す file_path も symlink 先に解決される
#[test]
fn symlink_になっているファイル自体を指す_file_path_も_symlink_先に解決される() {
    let tmp = tmp_root();
    let root = real_root(&tmp);
    fs::create_dir_all(root.join("src/allowed")).unwrap();
    fs::create_dir_all(root.join("src/protected")).unwrap();
    fs::write(root.join("src/protected/app.ts"), "").unwrap();
    std::os::unix::fs::symlink("../protected/app.ts", root.join("src/allowed/link.ts")).unwrap();

    let resolved = resolve_under_root(&root.join("src/allowed/link.ts"), &root).unwrap();

    assert_eq!(resolved.relative, Path::new("src/protected/app.ts"));
    assert!(resolved.moved);
}

// T-471: 未作成のディレクトリを含む file_path は最寄りの実在祖先まで遡って解決される
#[test]
fn 未作成のディレクトリを含む_file_path_は最寄りの実在祖先まで遡って解決される() {
    let tmp = tmp_root();
    let root = real_root(&tmp);
    fs::create_dir_all(root.join("src/allowed")).unwrap();
    fs::create_dir_all(root.join("src/protected")).unwrap();
    std::os::unix::fs::symlink("../protected", root.join("src/allowed/esc")).unwrap();

    // 末尾 2 段が未作成。親を 1 段だけ canonicalize する形では symlink に届かない。
    let resolved = resolve_under_root(&root.join("src/allowed/esc/fresh/app.ts"), &root).unwrap();

    assert_eq!(resolved.relative, Path::new("src/protected/fresh/app.ts"));
    assert!(resolved.moved);
}

// T-472: `..` で root の外へ出る file_path は None を返す
#[test]
fn dotdot_で_root_の外へ出る_file_path_は_none_を返す() {
    let tmp = tmp_root();
    let root = real_root(&tmp);
    fs::create_dir_all(root.join("src")).unwrap();

    let escaping = root.join("src").join("..").join("..").join("secret.ts");

    assert!(resolve_under_root(&escaping, &root).is_none());
}

// symlink を経ない実在パスでは moved が立たない
#[test]
fn symlink_を経ない実在パスでは_moved_が立たない() {
    let tmp = tmp_root();
    let root = real_root(&tmp);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/app.ts"), "").unwrap();

    let resolved = resolve_under_root(&root.join("src/app.ts"), &root).unwrap();

    assert_eq!(resolved.relative, Path::new("src/app.ts"));
    assert!(!resolved.moved);
}

// 相対パスは root へ join してから解決される
#[test]
fn 相対パスは_root_へ_join_してから解決される() {
    let tmp = tmp_root();
    let root = real_root(&tmp);

    let resolved = resolve_under_root(Path::new("src/app.ts"), &root).unwrap();

    assert_eq!(resolved.relative, Path::new("src/app.ts"));
    assert!(!resolved.moved);
}
