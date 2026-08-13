use crate::rules::Severity;
use globset::{Glob, GlobBuilder};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};

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

            /// Serde names of rules `before` had on and `self` has off, in
            /// declaration order. Drives the override-disable note in
            /// `effective_rules_with_notes` without hand-listing every field.
            pub(crate) fn disabled_since(&self, before: &RulesConfig) -> Vec<&'static str> {
                let mut disabled = Vec::new();
                $(if before.$field && !self.$field { disabled.push($serde_name); })*
                disabled
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
    /// `overrides[].files` patterns that failed to compile as a glob, in
    /// config-declaration order. The whole entry containing a failing
    /// pattern is dropped (see `compile_override_entry`); this list is what
    /// lets `effective_rules_with_notes` surface that drop instead of
    /// silently ignoring the entry.
    pub invalid_override_patterns: Vec<String>,
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
            invalid_override_patterns: Vec::new(),
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
            let mut overrides = Vec::new();
            let mut invalid_patterns = Vec::new();
            for raw in raw_overrides {
                match Self::compile_override_entry(raw) {
                    Ok(entry) => overrides.push(entry),
                    Err(failed_patterns) => invalid_patterns.extend(failed_patterns),
                }
            }
            self.overrides = overrides;
            self.invalid_override_patterns = invalid_patterns;
        }
        self
    }

    /// Compiles an override entry's glob patterns with `literal_separator(true)`
    /// so `*`/`?` do not cross a `/` boundary, matching eslint's glob semantics
    /// instead of globset's cross-`/` default
    /// (<https://docs.rs/globset/0.4.20/globset/struct.GlobBuilder.html#method.literal_separator>).
    /// An entry with any glob that fails to compile is dropped whole; other
    /// entries in the same config are kept. The failing pattern(s) are
    /// returned so the caller can populate `invalid_override_patterns` and
    /// the hook boundary can surface a note instead of dropping the entry
    /// silently (T-464).
    fn compile_override_entry(raw: ProjectOverrideEntry) -> Result<OverrideEntry, Vec<String>> {
        let mut files = Vec::with_capacity(raw.files.len());
        let mut failed_patterns = Vec::new();
        for pattern in raw.files {
            match GlobBuilder::new(&pattern).literal_separator(true).build() {
                Ok(glob) => files.push(glob),
                Err(_) => failed_patterns.push(pattern),
            }
        }
        if failed_patterns.is_empty() {
            Ok(OverrideEntry {
                files,
                rules: raw.rules,
            })
        } else {
            Err(failed_patterns)
        }
    }

    pub(crate) fn find_git_root(start: &Path) -> Option<PathBuf> {
        start
            .ancestors()
            .find(|d| d.join(".git").exists())
            .map(Path::to_path_buf)
    }

    /// Drops the notes from `effective_rules_with_notes`. Test-only: the hook
    /// boundary always wants the notes, so production has no caller that
    /// discards them.
    #[cfg(test)]
    pub(crate) fn effective_rules(&self, file_path: impl AsRef<Path>) -> RulesConfig {
        self.effective_rules_with_notes(file_path).0
    }

    /// Rule toggles effective for `file_path`: `self.rules` with every
    /// matching override's rules layered on top in listed order, merged key
    /// by key via `RulesConfig::apply_overrides` (eslint overrides semantics:
    /// a later match wins per rule key, not a whole-object replacement).
    ///
    /// When `git_root` is known, `file_path` is resolved against it and
    /// normalized (see `normalize_relative_to_root`) before matching, so
    /// patterns are always evaluated against a git-root-relative path.
    /// A `file_path` that normalizes outside `git_root` (escaping via `..`)
    /// matches no override. Without a known `git_root`, `file_path` is
    /// matched as given (legacy behavior for callers with no repo context).
    ///
    /// Paired with the toggles is one note per matching override entry that
    /// disables at least one rule (name + the matched pattern), for the hook
    /// boundary to surface.
    ///
    /// Also carries one note per pattern in `invalid_override_patterns`
    /// (an `overrides[].files` glob that failed to compile, whole entry
    /// dropped at config load — see `compile_override_entry`). Unlike the
    /// match-dependent notes below, this is a config-file defect, so it is
    /// reported for every call regardless of whether `file_path` matches
    /// anything, including when `file_path` escapes `git_root`.
    pub fn effective_rules_with_notes(
        &self,
        file_path: impl AsRef<Path>,
    ) -> (RulesConfig, Vec<String>) {
        let file_path = file_path.as_ref();
        let mut rules = self.rules.clone();
        let mut notes: Vec<String> = self
            .invalid_override_patterns
            .iter()
            .map(|pattern| {
                format!("override entry dropped: glob pattern \"{pattern}\" failed to compile")
            })
            .collect();

        let match_target = match &self.git_root {
            Some(root) => Self::normalize_relative_to_root(file_path, root),
            None => Some(file_path.to_path_buf()),
        };
        let Some(match_target) = match_target else {
            return (rules, notes);
        };

        for entry in &self.overrides {
            let matched_patterns: Vec<&str> = entry
                .files
                .iter()
                .filter(|glob| glob.compile_matcher().is_match(&match_target))
                .map(Glob::glob)
                .collect();
            if matched_patterns.is_empty() {
                continue;
            }
            let before = rules.clone();
            rules.apply_overrides(entry.rules.clone());
            let disabled = rules.disabled_since(&before);
            if !disabled.is_empty() {
                notes.push(format!(
                    "override disabled rule(s) [{}] for pattern(s) [{}]",
                    disabled.join(", "),
                    matched_patterns.join(", "),
                ));
            }
        }
        (rules, notes)
    }

    /// Resolves `file_path` against `git_root` and returns it relative to
    /// `git_root`, or `None` when it falls outside `git_root`.
    ///
    /// `file_path` is not required to exist on disk (a `PreToolUse` hook may
    /// see a file about to be created), so `Path::canonicalize` cannot be
    /// used here: it resolves symlinks and requires the path to exist.
    /// Instead `.` and `..` are resolved lexically by folding
    /// `Path::components` (`ParentDir` pops the last pushed `Normal`
    /// component, `CurDir` is dropped), mirroring what `canonicalize` would
    /// do for the path-syntax part alone.
    fn normalize_relative_to_root(file_path: &Path, git_root: &Path) -> Option<PathBuf> {
        let absolute = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            git_root.join(file_path)
        };

        let mut normalized: Vec<Component> = Vec::new();
        for component in absolute.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if matches!(normalized.last(), Some(Component::Normal(_))) {
                        normalized.pop();
                    } else {
                        normalized.push(component);
                    }
                }
                other => normalized.push(other),
            }
        }
        let normalized: PathBuf = normalized.into_iter().collect();

        normalized
            .strip_prefix(git_root)
            .ok()
            .map(Path::to_path_buf)
    }
}

#[cfg(test)]
mod tests;
