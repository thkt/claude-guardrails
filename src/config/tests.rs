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
