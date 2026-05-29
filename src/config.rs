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
mod tests;
