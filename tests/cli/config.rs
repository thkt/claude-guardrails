use crate::common::{
    clean_write_json, run_guardrails_in_dir, run_guardrails_with, tmp_repo, tmp_repo_with_claude,
};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

#[test]
fn hint_shown_when_claude_dir_exists_without_tools_json() {
    let tmp = tmp_repo_with_claude();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("using defaults"),
        "expected config hint in: {stderr}"
    );
    assert!(
        !tmp.path().join(".claude/tools.json").exists(),
        "hook must not create tools.json"
    );
}

#[test]
fn hint_shown_repeatedly_when_tools_json_absent() {
    let tmp = tmp_repo_with_claude();

    let stderr1 =
        String::from_utf8_lossy(&run_guardrails_in_dir(&clean_write_json(), tmp.path()).stderr)
            .into_owned();
    assert!(
        stderr1.contains("using defaults"),
        "first run hint missing: {stderr1}"
    );

    let stderr2 =
        String::from_utf8_lossy(&run_guardrails_in_dir(&clean_write_json(), tmp.path()).stderr)
            .into_owned();
    assert!(
        stderr2.contains("using defaults"),
        "hint must keep appearing each run while tools.json is absent: {stderr2}"
    );
}

#[test]
fn hint_shown_when_tools_json_without_guardrails_key() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(".claude/tools.json"), r#"{"reviews": {}}"#).unwrap();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("using defaults"),
        "expected config hint in: {stderr}"
    );
}

#[test]
fn no_hint_when_guardrails_configured() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {}}"#,
    )
    .unwrap();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("using defaults"),
        "unexpected config hint in: {stderr}"
    );
}

#[test]
fn no_hint_when_no_claude_dir() {
    let tmp = tmp_repo();

    let output = run_guardrails_in_dir(&clean_write_json(), tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("using defaults"),
        "unexpected config hint without .claude/ dir: {stderr}"
    );
}

// Malformed `.claude/tools.json` silently falls back to default config; the
// JSON envelope must mark this as degraded so AI consumers notice they are
// not running the project's rule set.
#[test]
fn malformed_tools_json_marks_json_envelope_degraded() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(".claude/tools.json"), "{not json}").unwrap();

    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(
        parsed["degraded"], true,
        "expected degraded:true when tools.json is malformed; got: {parsed}"
    );
    let notes = parsed["notes"].as_array().expect("notes must be an array");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("invalid config")),
        "expected a config-error note in envelope; got: {notes:?}"
    );
}

// F-008 gap 1: enabled:false at top level skips all rule evaluation.
#[test]
fn disabled_config_skips_rule_evaluation() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {"enabled": false}}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), tmp.path());
    assert_eq!(
        output.status.code(),
        Some(0),
        "enabled:false must skip eval rule; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// F-008 gap 2: enabled:false + --json emits an allow decision with zero violations.
#[test]
fn disabled_config_with_json_emits_allow_decision() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {"enabled": false}}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    assert_eq!(parsed["data"]["decision"], "allow");
    assert!(
        parsed["data"]["violations"]
            .as_array()
            .expect("violations array")
            .is_empty(),
        "enabled:false must yield zero violations: {parsed}"
    );
}

// F-008 gap 4: a malformed `.claude/tools.json` must fall back to default
// config so violation detection keeps running (binary-level, non-JSON path).
// The existing `malformed_tools_json_marks_json_envelope_degraded` covers the
// --json envelope side; this covers the stderr / exit-code side.
#[test]
fn malformed_config_falls_back_to_defaults_and_keeps_detecting() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(".claude/tools.json"), "{not json}").unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/src/app.ts",
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), tmp.path());
    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed config must fall back to defaults and still block eval; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BLOCKED") || stderr.contains("eval"),
        "expected eval violation despite config error: {stderr}"
    );
}

// The four below run the real binary, so `overrides` is read from disk,
// matched against the incoming `file_path`, and reflected in the exit code
// and the JSON envelope. A unit-level call into
// `resolve_effective_rules_with_notes` would skip the config-load and
// exit-code ends of that chain.

// T-462: overrides の pattern に一致するパスへの Write は exit 0 で通る
#[test]
fn overrides_の_pattern_に一致するパスへの_write_は_exit_0で通る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/allowed/**"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    // Claude Code sends an absolute file_path, so the seam runs the branch that
    // shape takes. A relative fixture would only cover `git_root.join`.
    // The root is canonicalized because on macOS the tempdir sits under a
    // symlinked `/var`; `current_dir` resolves it while the file_path here
    // would not, and the mismatch is a separate axis from what this asserts.
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/allowed/app.ts"),
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(0),
        "path matching the override pattern must skip the disabled eval rule; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-463: 同じ content を overrides の外のパスへ書くと exit 2 で止まる
#[test]
fn 同じ_content_を_overrides_の外のパスへ書くと_exit_2で止まる() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/allowed/**"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/other/app.ts"),
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(2),
        "path outside the override pattern must keep the eval rule active; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-464: compile できない glob を書いた config では note が JSON envelope に出る
#[test]
fn compile_できない_globを書いたconfigではnoteがjson_envelopeに出る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/[invalid"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    let notes = parsed["notes"].as_array().expect("notes must be an array");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("src/[invalid")),
        "expected a note naming the uncompilable override glob \"src/[invalid\"; got: {notes:?}"
    );
}

// T-466: hook mode で override の note が stderr に出る
#[test]
fn hook_mode_で_override_のnoteがstderrに出る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/allowed/**"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/allowed/app.ts"),
            "content": "eval(userInput);\n"
        }
    });
    // `--json` を渡さない、Claude Code が hook を起動するときの形。envelope は
    // 出ず、stdout には note を含む hook JSON が出る。stderr にも同じ note が
    // 出ることを見るのがこのテストで、notes の vec を見る assert では stderr
    // 経路が空でも通ってしまう。
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(&root),
        &[("NO_COLOR", "1")],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("override disabled rule(s) [eval]"),
        "expected the override note on stderr; got: {stderr:?}"
    );
}

// T-505: astSecurity を切る override を書いた repository で stderr の note に rule_id 数が出る
#[test]
fn astsecurity_を切る_overrideを書いたrepositoryでstderrのnoteにrule_id数が出る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/allowed/**"], "rules": {"astSecurity": false}}]}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/allowed/app.ts"),
            "content": "export const x = 1;\n"
        }
    });
    // `--json` を渡さない、Claude Code が hook を起動するときの形。T-466 と同じ形で
    // stderr を見る。
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(&root),
        &[("NO_COLOR", "1")],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("override disabled rule(s) [astSecurity]")
            && stderr.contains("astSecurity stops 14 rule_id(s)"),
        "expected the override note on stderr to carry astSecurity's own count; got: {stderr:?}"
    );
}

// T-506: eval を切る override の note が既存の書式のまま読める
#[test]
fn evalを切るoverrideのnoteが既存の書式のまま読める() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/allowed/**"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/allowed/app.ts"),
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(&root),
        &[("NO_COLOR", "1")],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("override disabled rule(s) [eval] for pattern(s) [src/allowed/**] (eval stops 1 rule_id(s))"),
        "expected the T-466 note format to still hold, now with the rule_id count appended; got: {stderr:?}"
    );
}

// T-512: JSON envelope の notes に compile 失敗の note がちょうど 1 件入る
#[test]
fn json_envelope_の_notes_に_compile_失敗の_note_がちょうど_1_件入る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/[invalid"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &["--json"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON envelope");
    let notes = parsed["notes"].as_array().expect("notes must be an array");
    // T-464 only checked `.any(...)`, which passes whether the note appears
    // once or is duplicated across the load-time and per-file note paths.
    // Counting catches a regression that emits the same compile-failure note
    // more than once.
    let matching = notes
        .iter()
        .filter(|n| n.as_str().unwrap_or("").contains("src/[invalid"))
        .count();
    assert_eq!(
        matching, 1,
        "expected exactly one note naming the uncompilable override glob \"src/[invalid\"; got: {notes:?}"
    );
}

// T-513: `--json` 無しの hook mode でも同じ note が stderr に 1 行だけ出る
#[test]
fn json_無しの_hook_mode_でも同じ_note_が_stderr_に_1_行だけ出る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/[invalid"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/app.ts",
            "content": "export const x = 1;\n"
        }
    });
    // `--json` を渡さない、Claude Code が hook を起動するときの形。T-466 / T-505
    // と同じ形で stderr を見るが、ここは件数を数える。
    let output = run_guardrails_with(
        json.to_string().as_bytes(),
        Some(tmp.path()),
        &[("NO_COLOR", "1")],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let occurrences = stderr
        .matches("glob pattern \"src/[invalid\" failed to compile")
        .count();
    assert_eq!(
        occurrences, 1,
        "expected the compile-failure note on stderr exactly once; got: {stderr:?}"
    );
}

/// `src/allowed/**` で eval を切る config と `src/allowed/esc -> ../protected`
/// を持つ repository を組み、`TempDir` と実体の root を返す。`TempDir` を落とす
/// とディレクトリごと消えるので、呼び出し側で束縛したまま保持する。
fn repo_with_escape_symlink() -> (tempfile::TempDir, PathBuf) {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"overrides": [{"files": ["src/allowed/**"], "rules": {"eval": false}}]}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    fs::create_dir_all(root.join("src/allowed")).unwrap();
    fs::create_dir_all(root.join("src/protected")).unwrap();
    symlink("../protected", root.join("src/allowed/esc")).unwrap();
    (tmp, root)
}

// T-477: override の対象外へ向く symlink を経由した Write は exit 2 で止まる
#[test]
fn override_の対象外へ向く_symlink_を経由した_write_は_exit_2で止まる() {
    let (_tmp, root) = repo_with_escape_symlink();

    // 綴りは override の対象内だが、この Write が作るファイルは src/protected に落ちる。
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/allowed/esc/app.ts"),
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a path spelled through a symlink must be judged at its target; stderr: {stderr}"
    );
    assert!(
        stderr.contains("followed a symlink"),
        "the resolution must be visible in a note; stderr: {stderr}"
    );
}

// T-478: symlink を経由しない override 対象パスへの同じ Write は exit 0 で通る
#[test]
fn symlink_を経由しない_override_対象パスへの同じ_write_は_exit_0で通る() {
    let (_tmp, root) = repo_with_escape_symlink();

    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("src/allowed/app.ts"),
            "content": "eval(userInput);\n"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the same repository must keep applying the override to non-symlinked paths; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-486: `.guardrails.json` へ overrides を書き足す Write は exit 2 で止まる
#[test]
fn guardrails_json_へ_overrides_を書き足す_write_は_exit_2で止まる() {
    let tmp = tmp_repo();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join(".guardrails.json"),
            "content": r#"{"overrides":[{"files":["**"],"rules":{"eval":false}}]}"#
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(2),
        "config edits belong to a human; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-487: 同じ content を `docs/sample.json` へ書くと exit 0 で通る
#[test]
fn 同じ_content_を_docs_配下へ書くと_exit_0で通る() {
    let tmp = tmp_repo();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join("docs/sample.json"),
            "content": r#"{"overrides":[{"files":["**"],"rules":{"eval":false}}]}"#
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(0),
        "only the config guardrails reads is guarded; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-585: pin を消す Write が exit 2 で止まる
#[test]
fn pin_を消す_write_が_exit_2で止まる() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".invariants.json"),
        r#"{"config.json": {"featureFlag": true}}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join(".invariants.json"),
            "content": "{}"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(2),
        "dropping a declared pin from .invariants.json must block; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-586: pin を足す Write が exit 0 で通る
#[test]
fn pin_を足す_write_が_exit_0で通る() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".invariants.json"),
        r#"{"config.json": {"featureFlag": true}}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join(".invariants.json"),
            "content": r#"{"config.json": {"featureFlag": true}, "other.json": {"apiBase": "https://x"}}"#
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(0),
        "adding a pin on top of unchanged existing pins must not block; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-597: 宣言ファイル自身が repository 外への symlink でも pin を消す Write が exit 2 で止まる
#[test]
fn 宣言ファイルが_repository_外への_symlink_でも_pin_を消す_write_が_exit_2で止まる() {
    let tmp = tmp_repo();
    let outside = tempfile::TempDir::new().unwrap();
    let target = outside.path().join("pins.json");
    fs::write(&target, r#"{"config.json": {"featureFlag": true}}"#).unwrap();
    symlink(&target, tmp.path().join(".invariants.json")).unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join(".invariants.json"),
            "content": "{}"
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a declaration file reached through a symlink out of the repository must still block; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-587: pin が無い repository では発火しない
#[test]
fn pinが無いrepositoryでは発火しない() {
    let tmp = tmp_repo();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join(".invariants.json"),
            "content": r#"{"config.json": {"featureFlag": true}}"#
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a repository with no pre-existing .invariants.json must not trigger the guard; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// T-488: `severity.blockThreshold` を `critical` にした repository でも設定ファイルへの Write は exit 2 で止まる
#[test]
fn blockthreshold_を_critical_にしても設定ファイルへの_write_は_exit_2で止まる() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(".guardrails.json"),
        r#"{"severity": {"blockThreshold": "critical"}}"#,
    )
    .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let json = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": root.join(".guardrails.json"),
            "content": r#"{"rules":{"configGuard":false}}"#
        }
    });
    let output = run_guardrails_in_dir(&json.to_string(), &root);
    assert_eq!(
        output.status.code(),
        Some(2),
        "Critical stays blocking at the highest threshold; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
