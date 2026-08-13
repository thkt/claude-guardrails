use super::*;
use std::fs;

fn tmp_repo() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::create_dir(tmp.path().join(".git")).unwrap();
    tmp
}

fn tmp_repo_with_claude() -> tempfile::TempDir {
    let tmp = tmp_repo();
    fs::create_dir(tmp.path().join(".claude")).unwrap();
    tmp
}

#[test]
fn default_severity_threshold_is_high() {
    let config = Config::default();
    assert_eq!(config.severity.block_threshold, Severity::High);
    // Critical and High block; Medium and below warn.
    assert!(Severity::Critical >= config.severity.block_threshold);
    assert!(Severity::High >= config.severity.block_threshold);
    assert!(Severity::Medium < config.severity.block_threshold);
}

#[test]
fn find_git_root_from_project_dir() {
    let tmp = tmp_repo();
    let result = Config::find_git_root(tmp.path());
    assert_eq!(result, Some(tmp.path().to_path_buf()));
}

#[test]
fn find_git_root_from_deep_subdir() {
    let tmp = tmp_repo();
    let deep = tmp.path().join("src/components");
    fs::create_dir_all(&deep).unwrap();

    let result = Config::find_git_root(&deep);
    assert_eq!(result, Some(tmp.path().to_path_buf()));
}

#[test]
fn find_git_root_none_without_git() {
    let tmp = tempfile::TempDir::new().unwrap();
    assert_eq!(Config::find_git_root(tmp.path()), None);
}

#[test]
fn merge_partial_rules_override() {
    let base = Config::default();
    let project: ProjectConfig =
        serde_json::from_str(r#"{"rules": {"biome": false, "oxlint": false}}"#).unwrap();

    let merged = base.merge(project);
    assert!(!merged.rules.biome);
    assert!(!merged.rules.oxlint);
    assert!(merged.rules.sensitive_file);
    assert!(merged.rules.security);
}

#[test]
fn merge_enabled_override() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(r#"{"enabled": false}"#).unwrap();

    let merged = base.merge(project);
    assert!(!merged.enabled);
    assert!(merged.rules.sensitive_file);
}

#[test]
fn merge_severity_override() {
    let base = Config::default();
    let project: ProjectConfig =
        serde_json::from_str(r#"{"severity": {"blockThreshold": "critical"}}"#).unwrap();

    let merged = base.merge(project);
    assert_eq!(merged.severity.block_threshold, Severity::Critical);
}

#[test]
fn merge_empty_project_config_no_change() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(r"{}").unwrap();

    let merged = base.merge(project);
    assert!(merged.enabled);
    assert!(merged.rules.biome);
    assert!(merged.rules.oxlint);
    assert_eq!(merged.severity.block_threshold, Severity::High);
}

#[test]
fn with_project_overrides_from_guardrails_json() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(GUARDRAILS_CONFIG_FILE),
        r#"{"rules": {"biome": false}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(!config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn with_project_overrides_guardrails_json_takes_priority_over_tools_json() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(GUARDRAILS_CONFIG_FILE),
        r#"{"rules": {"biome": false}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"rules": {"oxlint": false}}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    // .guardrails.json wins: biome disabled, oxlint stays default-on
    assert!(!config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn with_project_overrides_guardrails_json_takes_priority_over_legacy() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(GUARDRAILS_CONFIG_FILE),
        r#"{"rules": {"biome": false}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join(LEGACY_CONFIG_FILE),
        r#"{"rules": {"oxlint": false}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(!config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn with_project_overrides_malformed_guardrails_json_returns_error() {
    let tmp = tmp_repo();
    fs::write(tmp.path().join(GUARDRAILS_CONFIG_FILE), "not valid json{{{").unwrap();

    let result = Config::default().with_overrides_from_root(tmp.path());
    assert!(matches!(result.unwrap_err(), ConfigError::Parse { .. }));
}

#[test]
fn with_project_overrides_from_tools_json() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"rules": {"biome": false}}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(!config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn with_project_overrides_from_legacy_config() {
    let tmp = tmp_repo();
    fs::write(
        tmp.path().join(LEGACY_CONFIG_FILE),
        r#"{"rules": {"biome": false}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(!config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn with_project_overrides_tools_json_takes_priority() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"rules": {"biome": false}}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join(LEGACY_CONFIG_FILE),
        r#"{"rules": {"oxlint": false}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(!config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn with_project_overrides_no_config_returns_unchanged() {
    let tmp = tmp_repo();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(config.rules.biome);
    assert!(config.rules.oxlint);
    assert_eq!(config.source, ConfigSource::Default);
}

#[test]
fn with_project_overrides_malformed_tools_json_returns_error() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(TOOLS_CONFIG_FILE), "not valid json{{{").unwrap();

    let result = Config::default().with_overrides_from_root(tmp.path());
    assert!(matches!(result.unwrap_err(), ConfigError::Parse { .. }));
}

#[test]
fn with_project_overrides_malformed_legacy_config_returns_error() {
    let tmp = tmp_repo();
    fs::write(tmp.path().join(LEGACY_CONFIG_FILE), "not valid json{{{").unwrap();

    let result = Config::default().with_overrides_from_root(tmp.path());
    assert!(matches!(result.unwrap_err(), ConfigError::Parse { .. }));
}

#[test]
fn with_project_overrides_tools_json_without_guardrails_key() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"reviews": {"some": "config"}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(config.rules.biome);
    assert!(config.rules.oxlint);
    assert_eq!(config.source, ConfigSource::Default);
}

#[test]
fn with_project_overrides_tools_json_without_guardrails_ignores_legacy() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"reviews": {"some": "config"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join(LEGACY_CONFIG_FILE),
        r#"{"rules": {"biome": false}}"#,
    )
    .unwrap();

    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(config.rules.biome);
    assert!(config.rules.oxlint);
}

#[test]
fn merge_sets_explicit_source() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(r"{}").unwrap();
    let merged = base.merge(project);
    assert_eq!(merged.source, ConfigSource::Explicit);
}

#[test]
fn with_overrides_with_config_sets_explicit_source() {
    let tmp = tmp_repo_with_claude();
    fs::write(tmp.path().join(TOOLS_CONFIG_FILE), r#"{"guardrails": {}}"#).unwrap();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert_eq!(config.source, ConfigSource::Explicit);
}

#[test]
fn default_oxlint_config_is_empty() {
    let config = Config::default();
    assert!(config.oxlint_config.deny.is_empty());
    assert!(config.oxlint_config.allow.is_empty());
}

// T-008: oxlint deny from tools.json
#[test]
fn oxlint_deny_from_tools_json() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"oxlint": {"deny": ["eslint/curly"]}}}"#,
    )
    .unwrap();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert_eq!(config.oxlint_config.deny, vec!["eslint/curly"]);
    assert!(config.oxlint_config.allow.is_empty());
}

// T-009: oxlint allow from tools.json
#[test]
fn oxlint_allow_from_tools_json() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"oxlint": {"allow": ["eslint/no-console"]}}}"#,
    )
    .unwrap();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert_eq!(config.oxlint_config.allow, vec!["eslint/no-console"]);
}

// T-011: biome=true does not error (backward compat)
#[test]
fn biome_true_does_not_error() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"rules": {"biome": true}}}"#,
    )
    .unwrap();
    let result = Config::default().with_overrides_from_root(tmp.path());
    assert!(result.is_ok());
}

// T-012: biome=false normal operation
#[test]
fn biome_false_normal_operation() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(TOOLS_CONFIG_FILE),
        r#"{"guardrails": {"rules": {"biome": false}}}"#,
    )
    .unwrap();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    assert!(!config.rules.biome);
}

// T-275: top-level diffAware:true turns the diff_aware flag on.
#[test]
fn merge_diff_aware_true_enables_flag() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(r#"{"diffAware": true}"#).unwrap();
    let merged = base.merge(project);
    assert!(merged.diff_aware);
}

// T-275: absent diffAware key leaves diff_aware off (default).
#[test]
fn diff_aware_defaults_off_when_key_absent() {
    assert!(!Config::default().diff_aware);
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(r"{}").unwrap();
    let merged = base.merge(project);
    assert!(!merged.diff_aware);
}

// T-448: overrides を書かない config は override を持たない状態で読める
#[test]
fn overrides_を書かない_config_は_override_を持たない状態で読める() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(r"{}").unwrap();
    let merged = base.merge(project);
    assert!(merged.overrides.is_empty());
}

// T-449: files と rules を持つ override entry がそのまま保持される
#[test]
fn files_と_rules_を持つ_override_entry_がそのまま保持される() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{"overrides": [{"files": ["src/**/*.test.ts"], "rules": {"testAssertion": false}}]}"#,
    )
    .unwrap();

    let merged = base.merge(project);
    assert_eq!(merged.overrides.len(), 1);
    let entry = &merged.overrides[0];
    assert_eq!(entry.files.len(), 1);
    assert_eq!(entry.files[0].glob().glob(), "src/**/*.test.ts");
    assert_eq!(entry.rules.test_assertion, Some(false));
}

// T-450: compile できない glob を含む entry は捨てられ、同じ config の他の entry は保持される
#[test]
fn compile_できない_glob_を含む_entry_は捨てられ_同じ_config_の他の_entry_は保持される() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{"overrides": [
            {"files": ["src/[invalid"], "rules": {"testAssertion": false}},
            {"files": ["src/**/*.spec.ts"], "rules": {"flakyTest": false}}
        ]}"#,
    )
    .unwrap();

    let merged = base.merge(project);
    assert_eq!(merged.overrides.len(), 1);
    let entry = &merged.overrides[0];
    assert_eq!(entry.files[0].glob().glob(), "src/**/*.spec.ts");
    assert_eq!(entry.rules.flaky_test, Some(false));
}

// T-451: compile できない glob を含む config でも rules の基底設定は default に戻らない
#[test]
fn compile_できない_glob_を含む_config_でも_rules_の基底設定は_default_に戻らない() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{
            "rules": {"testAssertion": false},
            "overrides": [
                {"files": ["src/[invalid"], "rules": {"flakyTest": false}}
            ]
        }"#,
    )
    .unwrap();

    let merged = base.merge(project);
    assert!(!merged.rules.test_assertion);
    assert!(merged.rules.sensitive_file);
    assert!(merged.overrides.is_empty());
}

// T-452: pattern にマッチする file_path では override が指定した toggle が false になる
#[test]
fn pattern_にマッチする_file_path_では_override_が指定した_toggle_が_false_になる() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{"overrides": [{"files": ["src/**/*.test.ts"], "rules": {"testAssertion": false}}]}"#,
    )
    .unwrap();
    let config = base.merge(project);

    let rules = config.effective_rules("src/foo.test.ts");
    assert!(!rules.test_assertion);
}

// T-453: pattern にマッチしない file_path では toggle が変わらない
#[test]
fn pattern_にマッチしない_file_path_では_toggle_が変わらない() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{"overrides": [{"files": ["src/**/*.test.ts"], "rules": {"testAssertion": false}}]}"#,
    )
    .unwrap();
    let config = base.merge(project);

    let rules = config.effective_rules("src/foo.ts");
    assert!(rules.test_assertion);
}

// T-454: 同じ rule key を持つ override が 2 件マッチすると後続の値が勝つ
#[test]
fn 同じ_rule_key_を持つ_override_が_2_件マッチすると後続の値が勝つ() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{"overrides": [
            {"files": ["src/**/*.ts"], "rules": {"testAssertion": false}},
            {"files": ["src/**/*.ts"], "rules": {"testAssertion": true}}
        ]}"#,
    )
    .unwrap();
    let config = base.merge(project);

    let rules = config.effective_rules("src/foo.ts");
    assert!(rules.test_assertion);
}

// T-455: 後続の override は先行の override が設定した別の rule key を消さない
#[test]
fn 後続の_override_は先行の_override_が設定した別の_rule_key_を消さない() {
    let base = Config::default();
    let project: ProjectConfig = serde_json::from_str(
        r#"{"overrides": [
            {"files": ["src/**/*.ts"], "rules": {"testAssertion": false}},
            {"files": ["src/**/*.ts"], "rules": {"flakyTest": false}}
        ]}"#,
    )
    .unwrap();
    let config = base.merge(project);

    let rules = config.effective_rules("src/foo.ts");
    assert!(!rules.test_assertion);
    assert!(!rules.flaky_test);
}

/// tmp git root に `.guardrails.json` を書き、そこから読んだ Config を返す。
/// `TempDir` は呼び出し側が束縛したまま保持すること。捨てるとディレクトリごと
/// 消え、git root が失われて override 解決が別の経路に落ちる。
fn repo_with_config(json: &str) -> (tempfile::TempDir, Config) {
    let tmp = tmp_repo();
    fs::write(tmp.path().join(GUARDRAILS_CONFIG_FILE), json).unwrap();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();
    (tmp, config)
}

// T-456: `..` で git root の外へ出る file_path には override が適用されず rule が有効なままになる
#[test]
fn dotdot_で_git_root_の外へ出る_file_path_には_override_が適用されず_rule_が有効なままになる() {
    let (tmp, config) = repo_with_config(
        r#"{"overrides": [{"files": ["**/secret.ts"], "rules": {"testAssertion": false}}]}"#,
    );

    // git root の外 (親の親) へ `..` で抜けたうえで "secret.ts" に戻ってくる file_path。
    // `Path::components` で畳み込むと git root の外側を指し、root 相対化できない。
    let escaping_path = tmp
        .path()
        .join("src")
        .join("..")
        .join("..")
        .join("secret.ts");

    let rules = config.effective_rules(&escaping_path);
    assert!(rules.test_assertion);
}

// T-465: root 相対化できない file_path では override を飛ばしたことが note に出る
#[test]
fn root相対化できない_file_path_では_override_を飛ばしたことが_note_に出る() {
    let (tmp, config) = repo_with_config(
        r#"{"overrides": [{"files": ["**/secret.ts"], "rules": {"testAssertion": false}}]}"#,
    );

    // 相対化できない経路は 2 つあり、どちらも rule を有効なまま残す。`..` で
    // repository の外へ出る形と、symlink 経由の root (`current_dir` は実体へ
    // 解決するが agent が送る file_path は解決しない) がそれで、出力は同じ。
    // note が無いと利用者は override を書いたのに効かない理由を追えない。
    let escaping_path = tmp.path().join("..").join("..").join("secret.ts");

    let (rules, notes) = config.effective_rules_with_notes(&escaping_path);
    assert!(rules.test_assertion);
    assert!(
        notes
            .iter()
            .any(|n| n.contains("override matching skipped")),
        "expected a note naming the skipped path; got: {notes:?}"
    );
}

// T-457: `src/*.ts` は `src/api/db.ts` にマッチしない
#[test]
fn src_star_ts_は_src_api_db_ts_にマッチしない() {
    let (tmp, config) = repo_with_config(
        r#"{"overrides": [{"files": ["src/*.ts"], "rules": {"testAssertion": false}}]}"#,
    );

    let nested_path = tmp.path().join("src").join("api").join("db.ts");

    let rules = config.effective_rules(&nested_path);
    assert!(rules.test_assertion);
}

// T-458: 絶対パスで書いた pattern は git root 相対のマッチ対象に一致しない
#[test]
fn 絶対パスで書いた_pattern_は_git_root_相対のマッチ対象に一致しない() {
    let tmp = tmp_repo();
    let target_path = tmp.path().join("src").join("foo.ts");
    let absolute_pattern = target_path.to_string_lossy().into_owned();
    fs::write(
        tmp.path().join(GUARDRAILS_CONFIG_FILE),
        format!(
            r#"{{"overrides": [{{"files": ["{absolute_pattern}"], "rules": {{"testAssertion": false}}}}]}}"#
        ),
    )
    .unwrap();
    let config = Config::default()
        .with_overrides_from_root(tmp.path())
        .unwrap();

    let rules = config.effective_rules(&target_path);
    assert!(rules.test_assertion);
}
