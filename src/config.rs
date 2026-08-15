use crate::path_resolve::{self, Resolved};
use crate::rules::{toggle_rule_id_count, Severity};
use globset::{GlobBuilder, GlobMatcher};
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
    config_guard      => "configGuard",
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigSource {
    Default,
    Explicit,
}

impl RulesConfig {
    /// `config_guard` stays at its `rules` value: an entry switching it off for
    /// `.guardrails.json` would let the next edit take the guard out.
    fn apply_path_overrides(&mut self, project: ProjectRulesConfig) {
        let guard = self.config_guard;
        self.apply_overrides(project);
        self.config_guard = guard;
    }
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
    pub files: Vec<GlobMatcher>,
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
pub(crate) const LEGACY_CONFIG_FILE: &str = ".claude-guardrails.json";

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
    /// Returns the load-time notes alongside the config (see
    /// `invalid_pattern_note`).
    pub fn with_project_overrides(self) -> Result<(Self, Vec<String>), ConfigError> {
        let cwd = env::current_dir().map_err(ConfigError::WorkingDir)?;
        self.with_overrides_from_root(&cwd)
    }

    fn with_overrides_from_root(
        mut self,
        start: &Path,
    ) -> Result<(Self, Vec<String>), ConfigError> {
        let Some(git_root) = Self::find_git_root(start) else {
            return Ok((self, Vec::new()));
        };
        self.git_root = Some(git_root.clone());

        let agent_neutral_path = git_root.join(GUARDRAILS_CONFIG_FILE);
        if let Some(content) = read_optional_config(&agent_neutral_path)? {
            let project: ProjectConfig =
                serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: agent_neutral_path,
                    source: e,
                })?;
            return Ok(self.merge_with_notes(project));
        }

        let tools_path = git_root.join(TOOLS_CONFIG_FILE);
        if let Some(content) = read_optional_config(&tools_path)? {
            let tools: ToolsConfig =
                serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: tools_path,
                    source: e,
                })?;
            if let Some(project) = tools.guardrails {
                return Ok(self.merge_with_notes(project));
            }
            return Ok((self, Vec::new()));
        }

        let legacy_path = git_root.join(LEGACY_CONFIG_FILE);
        if let Some(content) = read_optional_config(&legacy_path)? {
            let project: ProjectConfig =
                serde_json::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: legacy_path,
                    source: e,
                })?;
            return Ok(self.merge_with_notes(project));
        }

        Ok((self, Vec::new()))
    }

    /// Note-discarding form for tests that assert on the merged fields alone.
    #[cfg(test)]
    fn merge(self, project: ProjectConfig) -> Self {
        self.merge_with_notes(project).0
    }

    /// Failed patterns leave through the returned notes rather than onto
    /// `Config`, which carries settings and not diagnostics.
    fn merge_with_notes(mut self, project: ProjectConfig) -> (Self, Vec<String>) {
        let mut notes = Vec::new();
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
            for raw in raw_overrides {
                match Self::compile_override_entry(raw) {
                    Ok(entry) => overrides.push(entry),
                    Err(failed_patterns) => notes.extend(
                        failed_patterns
                            .iter()
                            .map(|pattern| Self::invalid_pattern_note(pattern)),
                    ),
                }
            }
            self.overrides = overrides;
        }
        (self, notes)
    }

    /// Compiles an override entry's glob patterns with `literal_separator(true)`
    /// so `*`/`?` do not cross a `/` boundary, matching eslint's glob semantics
    /// instead of globset's cross-`/` default
    /// (<https://docs.rs/globset/0.4.20/globset/struct.GlobBuilder.html#method.literal_separator>).
    /// An entry with any glob that fails to compile is dropped whole; other
    /// entries in the same config are kept. The failing pattern(s) are
    /// returned so `merge_with_notes` can turn them into notes and the
    /// hook boundary can surface those instead of dropping the entry
    /// silently.
    fn compile_override_entry(raw: ProjectOverrideEntry) -> Result<OverrideEntry, Vec<String>> {
        let mut files = Vec::with_capacity(raw.files.len());
        let mut failed_patterns = Vec::new();
        for pattern in raw.files {
            match GlobBuilder::new(&pattern).literal_separator(true).build() {
                Ok(glob) => files.push(glob.compile_matcher()),
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

    /// Load-time only. This note does not depend on `file_path`, so emitting
    /// it per file would repeat one config defect on every hook invocation.
    fn invalid_pattern_note(pattern: &str) -> String {
        format!("override entry dropped: glob pattern \"{pattern}\" failed to compile")
    }

    pub(crate) fn find_git_root(start: &Path) -> Option<PathBuf> {
        start
            .ancestors()
            .find(|d| d.join(".git").exists())
            .map(Path::to_path_buf)
    }

    /// Drops the notes from `effective_rules_with_notes`.
    #[cfg(test)]
    pub(crate) fn effective_rules(&self, file_path: impl AsRef<Path>) -> RulesConfig {
        self.effective_rules_with_notes(file_path).0
    }

    /// Rule toggles effective for `file_path`: `self.rules` with every
    /// matching override's rules layered on top in listed order, merged key
    /// by key via `RulesConfig::apply_overrides` (eslint overrides semantics:
    /// a later match wins per rule key, not a whole-object replacement).
    ///
    /// Patterns are matched against a git-root-relative path resolved by
    /// `path_resolve::resolve_under_root`, so a `file_path` escaping
    /// `git_root` via `..` matches no override, and one spelled through a
    /// symlink matches the patterns its target sits under. Without a known
    /// `git_root` the path is matched as given; production never takes that
    /// branch, since `with_overrides_from_root` leaves `overrides` empty when
    /// it finds no root.
    ///
    /// The notes are for the hook boundary to surface: one per matching
    /// entry that disables at least one rule (rule names + matched
    /// patterns), and one when resolution moved the path. A glob that failed
    /// to compile is not among them (see `invalid_pattern_note`).
    pub fn effective_rules_with_notes(
        &self,
        file_path: impl AsRef<Path>,
    ) -> (RulesConfig, Vec<String>) {
        let file_path = file_path.as_ref();
        let mut rules = self.rules.clone();
        let mut notes: Vec<String> = Vec::new();

        // Skipping the normalization below keeps its cost off every hook
        // invocation in a repository that writes no `overrides` key.
        if self.overrides.is_empty() {
            return (rules, notes);
        }

        let resolved = match &self.git_root {
            Some(root) => path_resolve::resolve_under_root(file_path, root),
            None => Some(Resolved {
                relative: file_path.to_path_buf(),
                moved: false,
            }),
        };
        // Two situations reach this branch and neither is visible otherwise:
        // a `..` that climbs out of the repository, and a root reached
        // through a symlink (`current_dir` resolves it, the agent-supplied
        // `file_path` does not, so `strip_prefix` misses). Both leave every
        // rule enabled — the safe direction, but it drops what the user
        // wrote, so say so.
        let Some(resolved) = resolved else {
            notes.push(format!(
                "override matching skipped: {} did not resolve under the repository root",
                file_path.display(),
            ));
            return (rules, notes);
        };
        // Without this the patterns that matched are not the ones the spelling
        // suggests, and nothing says so.
        if resolved.moved {
            notes.push(format!(
                "override matching followed a symlink: {} resolves to {}",
                file_path.display(),
                resolved.relative.display(),
            ));
        }
        let match_target = resolved.relative;

        for entry in &self.overrides {
            let matched_patterns: Vec<&str> = entry
                .files
                .iter()
                .filter(|matcher| matcher.is_match(&match_target))
                .map(|matcher| matcher.glob().glob())
                .collect();
            if matched_patterns.is_empty() {
                continue;
            }
            let before = rules.clone();
            rules.apply_path_overrides(entry.rules.clone());
            let disabled = rules.disabled_since(&before);
            if !disabled.is_empty() {
                notes.push(format!(
                    "override disabled rule(s) [{}] for pattern(s) [{}]{}",
                    disabled.join(", "),
                    matched_patterns.join(", "),
                    Self::stopped_rule_id_summary(&disabled),
                ));
            }
        }
        (rules, notes)
    }

    /// How many `rule_id`s each disabled toggle stops firing, appended outside
    /// the bracketed lists so the existing note format stays greppable.
    ///
    /// Per toggle, never summed: `security` is emitted by the registry rule
    /// and by `ast_security`'s postMessage path alike, so adding two toggles'
    /// counts would claim more stopped checks than exist.
    fn stopped_rule_id_summary(disabled: &[&str]) -> String {
        let parts: Vec<String> = disabled
            .iter()
            .map(|&name| match toggle_rule_id_count(name) {
                Some(count) => format!("{name} stops {count} rule_id(s)"),
                None => format!("{name}: external linter"),
            })
            .collect();
        if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join("; "))
        }
    }
}

#[cfg(test)]
mod tests;
