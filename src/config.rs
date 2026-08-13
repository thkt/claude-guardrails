use crate::rules::Severity;
use globset::{Glob, GlobBuilder};
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

        #[derive(Debug, Clone, Deserialize)]
        pub(crate) struct ProjectRulesConfig {
            $(
                #[serde(rename = $serde_name)]
                pub(crate) $field: Option<bool>,
            )*
        }

        impl RulesConfig {
            fn apply_overrides(&mut self, project: ProjectRulesConfig) {
                $(if let Some(v) = project.$field { self.$field = v; })*
            }

            /// All toggles off: test-only base for single-toggle isolation
            /// (per-toggle latency diagnostics in the precision harness).
            #[cfg(test)]
            pub(crate) fn all_off() -> Self {
                Self { $($field: false,)* }
            }
        }

        /// Every public toggle name (the `.guardrails.json` `rules` keys). Test-only
        /// registry that lets `doc_catalog::config_toggles_match_rule_docs` pin this
        /// config contract against `RULE_DOCS`, mirroring `rule_id::RULE_ID_CATALOG`.
        #[cfg(test)]
        pub(crate) const RULE_TOGGLE_NAMES: &[&str] = &[ $( $serde_name ),* ];
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
    invariant         => "invariant",
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
    pub diff_aware: bool,
    pub source: ConfigSource,
    pub git_root: Option<PathBuf>,
    pub overrides: Vec<OverrideEntry>,
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

/// A single `.guardrails.json` `overrides` entry: file glob patterns paired
/// with the rule toggles that apply only to matching files.
#[derive(Debug, Clone)]
pub struct OverrideEntry {
    pub files: Vec<Glob>,
    pub rules: ProjectRulesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: RulesConfig::default(),
            severity: SeverityConfig::default(),
            oxlint_config: OxlintConfig::default(),
            diff_aware: false,
            source: ConfigSource::Default,
            git_root: None,
            overrides: Vec::new(),
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
    #[serde(rename = "diffAware")]
    diff_aware: Option<bool>,
    overrides: Option<Vec<ProjectOverrideEntry>>,
}

#[derive(Debug, Deserialize)]
struct ProjectOverrideEntry {
    files: Vec<String>,
    rules: ProjectRulesConfig,
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

/// Reads a config file that may legitimately be absent: missing file is
/// `None`, any other I/O failure is an error.
fn read_optional_config(path: &Path) -> Result<Option<String>, ConfigError> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() != ErrorKind::NotFound => Err(ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
        Err(_) => Ok(None),
    }
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
        if let Some(content) = read_optional_config(&agent_neutral_path)? {
            let project: ProjectConfig =
                serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: agent_neutral_path,
                    source: e,
                })?;
            return Ok(self.merge(project));
        }

        let tools_path = git_root.join(TOOLS_CONFIG_FILE);
        if let Some(content) = read_optional_config(&tools_path)? {
            let tools: ToolsConfig =
                serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: tools_path,
                    source: e,
                })?;
            if let Some(project) = tools.guardrails {
                return Ok(self.merge(project));
            }
            return Ok(self);
        }

        let legacy_path = git_root.join(LEGACY_CONFIG_FILE);
        if let Some(content) = read_optional_config(&legacy_path)? {
            let project: ProjectConfig =
                serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: legacy_path,
                    source: e,
                })?;
            return Ok(self.merge(project));
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
        if let Some(diff_aware) = project.diff_aware {
            self.diff_aware = diff_aware;
        }
        if let Some(raw_overrides) = project.overrides {
            self.overrides = raw_overrides
                .into_iter()
                .filter_map(Self::compile_override_entry)
                .collect();
        }
        self
    }

    /// Compiles an override entry's glob patterns with `literal_separator(true)`
    /// so `*`/`?` do not cross a `/` boundary, matching eslint's glob semantics
    /// instead of globset's cross-`/` default
    /// (<https://docs.rs/globset/0.4.20/globset/struct.GlobBuilder.html#method.literal_separator>).
    /// An entry with any glob that fails to compile is dropped whole; other
    /// entries in the same config are kept.
    fn compile_override_entry(raw: ProjectOverrideEntry) -> Option<OverrideEntry> {
        let files: Result<Vec<Glob>, globset::Error> = raw
            .files
            .iter()
            .map(|pattern| GlobBuilder::new(pattern).literal_separator(true).build())
            .collect();
        files.ok().map(|files| OverrideEntry {
            files,
            rules: raw.rules,
        })
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
