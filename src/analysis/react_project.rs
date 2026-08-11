//! React プロジェクト判定 (#424)。oxlint の `react/rules-of-hooks` は `.ts` に
//! 住む Vue/Nuxt の composable を React Hook と誤認して blocking するため、
//! plugin の有効化を「編集対象が react に依存する package に属するか」で絞る。
//! oxc は `.vue` / `.svelte` を拡張子で除外するが、composable は `.ts` に住むので
//! その除外は効かない。判定できないときは false を返し、検出を諦める側に倒す。

use serde_json::Value;
use std::fs;
use std::path::Path;

/// 編集対象から遡る階層数の上限。`src/resolve/tests.rs` の bench が深さ 10 の
/// 全 miss を最悪ケースとして測っており、同じ 10 を採る。上限に当たると false を
/// 返すので、これより深いファイルは検出を諦める側に倒れる。
const MAX_ANCESTOR_DEPTH: usize = 10;

/// react への依存を宣言しうる package.json のキー。workspace が react を root に
/// hoist し leaf は peer 宣言だけ持つ構成を落とさないため peerDependencies も見る。
const DEPENDENCY_KEYS: [&str; 3] = ["dependencies", "devDependencies", "peerDependencies"];

/// 最寄りの package.json ただ 1 個で判定する。上位に react を宣言する package.json
/// があっても、最寄りが宣言していなければ false。monorepo で Vue の package を
/// 編集したとき、root の react 依存で gate が開くのを防ぐ。
pub(crate) fn is_react_project(file_path: &str) -> bool {
    Path::new(file_path)
        .ancestors()
        .skip(1)
        .take(MAX_ANCESTOR_DEPTH)
        .find_map(|dir| fs::read_to_string(dir.join("package.json")).ok())
        .is_some_and(|manifest| declares_react(&manifest))
}

fn declares_react(manifest: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(manifest) else {
        return false;
    };
    DEPENDENCY_KEYS
        .iter()
        .any(|key| value.get(key).and_then(|deps| deps.get("react")).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn project(manifests: &[(&str, &str)]) -> TempDir {
        let root = TempDir::new().unwrap();
        for (dir, manifest) in manifests {
            let path = root.path().join(dir);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("package.json"), manifest).unwrap();
        }
        root
    }

    fn check(root: &TempDir, relative: &str) -> bool {
        is_react_project(root.path().join(relative).to_str().unwrap())
    }

    // Manual verification (#424): gate の per-call コスト。閾値 assert は
    // ランナー依存で割れるため置かず、eprintln で値だけ残す。
    #[test]
    fn bench_is_react_project() {
        use std::time::Instant;
        let root = project(&[(".", r#"{"dependencies": {"react": "^19.0.0"}}"#)]);
        let hit = root.path().join("src/hooks/useFetch.ts");
        let miss = root.path().join("a/b/c/d/e/f/g/h/i/j/k/deep.ts");
        for (label, path) in [("nearest hit", &hit), ("depth-limit miss", &miss)] {
            let iters = 1000u32;
            let start = Instant::now();
            for _ in 0..iters {
                let _ = is_react_project(path.to_str().unwrap());
            }
            let per_call_ns = start.elapsed().as_nanos() / u128::from(iters);
            eprintln!("bench: is_react_project ({label}) = {per_call_ns} ns");
        }
    }

    // T-428
    #[test]
    fn detects_a_react_project_when_the_nearest_package_json_lists_react_in_dependencies() {
        let root = project(&[(".", r#"{"dependencies": {"react": "^19.0.0"}}"#)]);
        assert!(check(&root, "src/hooks/useFetch.ts"));
    }

    // T-429: monorepo で Vue の package を編集したとき、root の react で開かない。
    #[test]
    fn does_not_detect_a_react_project_when_the_nearest_package_json_omits_react_even_if_an_ancestor_package_json_lists_it(
    ) {
        let root = project(&[
            (".", r#"{"dependencies": {"react": "^19.0.0"}}"#),
            ("packages/web", r#"{"dependencies": {"vue": "^3.5.0"}}"#),
        ]);
        assert!(!check(&root, "packages/web/composables/useCounter.ts"));
    }

    // T-430
    #[test]
    fn does_not_detect_a_react_project_when_no_package_json_exists_within_the_ancestor_depth_limit()
    {
        let root = project(&[(".", r#"{"dependencies": {"react": "^19.0.0"}}"#)]);
        assert!(!check(&root, "a/b/c/d/e/f/g/h/i/j/k/deep.ts"));
    }

    // T-431
    #[test]
    fn detects_a_react_project_when_react_appears_only_in_dev_dependencies_or_only_in_peer_dependencies(
    ) {
        let dev = project(&[(".", r#"{"devDependencies": {"react": "^19.0.0"}}"#)]);
        assert!(check(&dev, "src/hooks/useFetch.ts"));

        let peer = project(&[(".", r#"{"peerDependencies": {"react": ">=18"}}"#)]);
        assert!(check(&peer, "src/hooks/useFetch.ts"));
    }
}
