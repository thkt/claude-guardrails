use crate::rules::Severity;
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

/// Generates `RulesConfig` (runtime flags), `ProjectRulesConfig` (serde DTO),
/// `Default` impl (all rules enabled), and `apply_overrides` (partial merge).
/// Add a new rule by appending `field_name => "camelCaseName"` to the invocation.
macro_rules! define_rule_config {
    ($( $field:ident => $serde_name:literal ),* $(,)?) => {
        #[derive(Debug, Clone)]
        pub struct RulesConfig {
            $(pub $field: bool,)*
        }

        impl Default for RulesConfig {
            fn default() -> Self {
                Self { $($field: true,)* }
            }
        }

        #[derive(Debug, Deserialize)]
        struct ProjectRulesConfig {
            $(
                #[serde(rename = $serde_name)]
                $field: Option<bool>,
            )*
        }

        impl RulesConfig {
            fn apply_overrides(&mut self, project: ProjectRulesConfig) {
                $(if let Some(v) = project.$field { self.$field = v; })*
            }
        }
    };
}

define_rule_config! {
    sensitive_file    => "sensitiveFile",
    architecture      => "architecture",
    naming            => "naming",
    transaction       => "transaction",
    security          => "security",
    crypto_weak       => "cryptoWeak",
    generated_file    => "generatedFile",
    test_location     => "testLocation",
    dom_access        => "domAccess",
    sync_io           => "syncIo",
    bundle_size       => "bundleSize",
    test_assertion    => "testAssertion",
    flaky_test        => "flakyTest",
    sensitive_logging => "sensitiveLogging",
    no_use_effect     => "noUseEffect",
    biome             => "biome",
    oxlint            => "oxlint",
    eval              => "eval",
    hardcoded_secrets => "hardcodedSecrets",
    http_resource     => "httpResource",
    raw_html          => "rawHtml",
    open_redirect     => "openRedirect",
    ast_security      => "astSecurity",
    cot_leakage_marker => "cotLeakageMarker",
    sqli_concat       => "sqliConcat",
    cors_wildcard     => "corsWildcard",
    service_worker    => "serviceWorker",
    jwt_client        => "jwtClient",
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigSource {
    Default,
    Explicit,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub rules: RulesConfig,
    pub severity: SeverityConfig,
    pub oxlint_config: OxlintConfig,
    pub source: ConfigSource,
    pub git_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SeverityConfig {
    /// Violations at or above this severity block the tool; below it warn.
    pub block_threshold: Severity,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            block_threshold: Severity::High,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OxlintConfig {
    pub deny: Vec<String>,
    pub allow: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: RulesConfig::default(),
            severity: SeverityConfig::default(),
            oxlint_config: OxlintConfig::default(),
            source: ConfigSource::Default,
            git_root: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProjectOxlintConfig {
    deny: Option<Vec<String>>,
    allow: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ProjectConfig {
    enabled: Option<bool>,
    rules: Option<ProjectRulesConfig>,
    severity: Option<ProjectSeverityConfig>,
    oxlint: Option<ProjectOxlintConfig>,
}

#[derive(Debug, Deserialize)]
struct ProjectSeverityConfig {
    #[serde(rename = "blockThreshold")]
    block_threshold: Option<Severity>,
}

pub(crate) const GUARDRAILS_CONFIG_FILE: &str = ".guardrails.json";
pub(crate) const TOOLS_CONFIG_FILE: &str = ".claude/tools.json";
const LEGACY_CONFIG_FILE: &str = ".claude-guardrails.json";

#[derive(Debug, Deserialize)]
struct ToolsConfig {
    guardrails: Option<ProjectConfig>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("cannot determine working directory: {0}")]
    WorkingDir(#[source] io::Error),
    #[error("cannot read config {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid config {path:?}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

impl Config {
    // Uses CWD (not file_path) as trust boundary to prevent
    // LLM-controlled paths from influencing config discovery.
    pub fn with_project_overrides(self) -> Result<Self, ConfigError> {
        let cwd = env::current_dir().map_err(ConfigError::WorkingDir)?;
        self.with_overrides_from_root(&cwd)
    }

    fn with_overrides_from_root(mut self, start: &Path) -> Result<Self, ConfigError> {
        let Some(git_root) = Self::find_git_root(start) else {
            return Ok(self);
        };
        self.git_root = Some(git_root.clone());

        let agent_neutral_path = git_root.join(GUARDRAILS_CONFIG_FILE);
        match fs::read_to_string(&agent_neutral_path) {
            Ok(content) => {
                let project: ProjectConfig =
                    serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                        path: agent_neutral_path.clone(),
                        source: e,
                    })?;
                return Ok(self.merge(project));
            }
            Err(e) if e.kind() != ErrorKind::NotFound => {
                return Err(ConfigError::Io {
                    path: agent_neutral_path.clone(),
                    source: e,
                });
            }
            Err(_) => {}
        }

        let tools_path = git_root.join(TOOLS_CONFIG_FILE);
        match fs::read_to_string(&tools_path) {
            Ok(content) => {
                let tools: ToolsConfig =
                    serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                        path: tools_path.clone(),
                        source: e,
                    })?;
                if let Some(project) = tools.guardrails {
                    return Ok(self.merge(project));
                }
                return Ok(self);
            }
            Err(e) if e.kind() != ErrorKind::NotFound => {
                return Err(ConfigError::Io {
                    path: tools_path.clone(),
                    source: e,
                });
            }
            Err(_) => {}
        }

        let legacy_path = git_root.join(LEGACY_CONFIG_FILE);
        match fs::read_to_string(&legacy_path) {
            Ok(content) => {
                let project: ProjectConfig =
                    serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                        path: legacy_path.clone(),
                        source: e,
                    })?;
                return Ok(self.merge(project));
            }
            Err(e) if e.kind() != ErrorKind::NotFound => {
                return Err(ConfigError::Io {
                    path: legacy_path.clone(),
                    source: e,
                });
            }
            Err(_) => {}
        }

        Ok(self)
    }

    fn merge(mut self, project: ProjectConfig) -> Self {
        self.source = ConfigSource::Explicit;
        if let Some(enabled) = project.enabled {
            self.enabled = enabled;
        }
        if let Some(pr) = project.rules {
            if pr.biome == Some(true) {
                eprintln!(
                    "guardrails: warning: \"biome\" option is deprecated and ignored. oxlint is used instead."
                );
            }
            self.rules.apply_overrides(pr);
        }
        if let Some(ps) = project.severity {
            if let Some(threshold) = ps.block_threshold {
                self.severity.block_threshold = threshold;
            }
        }
        if let Some(oc) = project.oxlint {
            if let Some(deny) = oc.deny {
                self.oxlint_config.deny = deny;
            }
            if let Some(allow) = oc.allow {
                self.oxlint_config.allow = allow;
            }
        }
        self
    }

    pub(crate) fn find_git_root(start: &Path) -> Option<PathBuf> {
        start
            .ancestors()
            .find(|d| d.join(".git").exists())
            .map(Path::to_path_buf)
    }
}

#[cfg(test)]
mod tests {
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
}
