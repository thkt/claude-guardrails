use crate::rules::Severity;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub severity: SeverityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RulesConfig {
    #[serde(rename = "sensitiveFile", default = "default_true")]
    pub sensitive_file: bool,
    #[serde(default = "default_true")]
    pub architecture: bool,
    #[serde(default = "default_true")]
    pub naming: bool,
    #[serde(default = "default_true")]
    pub transaction: bool,
    #[serde(default = "default_true")]
    pub security: bool,
    #[serde(rename = "cryptoWeak", default = "default_true")]
    pub crypto_weak: bool,
    #[serde(rename = "generatedFile", default = "default_true")]
    pub generated_file: bool,
    #[serde(rename = "testLocation", default = "default_true")]
    pub test_location: bool,
    #[serde(rename = "domAccess", default = "default_true")]
    pub dom_access: bool,
    #[serde(rename = "syncIo", default = "default_true")]
    pub sync_io: bool,
    #[serde(rename = "bundleSize", default = "default_true")]
    pub bundle_size: bool,
    #[serde(rename = "testAssertion", default = "default_true")]
    pub test_assertion: bool,
    #[serde(rename = "flakyTest", default = "default_true")]
    pub flaky_test: bool,
    #[serde(rename = "sensitiveLogging", default = "default_true")]
    pub sensitive_logging: bool,
    #[serde(default = "default_true")]
    pub biome: bool,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            sensitive_file: true,
            architecture: true,
            naming: true,
            transaction: true,
            security: true,
            crypto_weak: true,
            generated_file: true,
            test_location: true,
            dom_access: true,
            sync_io: true,
            bundle_size: true,
            test_assertion: true,
            flaky_test: true,
            sensitive_logging: true,
            biome: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeverityConfig {
    #[serde(rename = "blockOn", default = "default_block_on")]
    pub block_on: Vec<Severity>,
}

fn default_true() -> bool {
    true
}

fn default_block_on() -> Vec<Severity> {
    vec![Severity::Critical, Severity::High]
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            block_on: default_block_on(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: RulesConfig::default(),
            severity: SeverityConfig::default(),
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let config_path = Self::config_path();

        match fs::read_to_string(&config_path) {
            Ok(content) => match serde_json::from_str::<Config>(&content) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!(
                        "guardrails: warning: invalid config at {:?}: {}",
                        config_path, e
                    );
                    eprintln!("guardrails: using default configuration");
                    Config::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => {
                eprintln!(
                    "guardrails: warning: cannot read config {:?}: {}",
                    config_path, e
                );
                Config::default()
            }
        }
    }

    fn config_path() -> PathBuf {
        Self::config_search_paths(std::env::current_exe().ok().as_deref())
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_default()
    }

    /// Generate config search paths without filesystem access (testable).
    fn config_search_paths(exe_path: Option<&std::path::Path>) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Some(exe_dir) = exe_path.and_then(|p| p.parent()) {
            paths.push(exe_dir.join("../../config.json"));
            paths.push(exe_dir.join("../config.json"));
            paths.push(exe_dir.join("config.json"));
        }

        paths.push(PathBuf::from("config.json"));

        if let Some(config_dir) = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        {
            paths.push(config_dir.join("guardrails/config.json"));
        }

        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_search_paths_with_exe() {
        let paths = Config::config_search_paths(Some(std::path::Path::new("/usr/bin/guardrails")));
        assert!(paths.iter().any(|p| p.ends_with("config.json")));
        assert!(paths.iter().any(|p| p.to_string_lossy().contains("/usr/")));
    }

    #[test]
    fn config_search_paths_without_exe() {
        let paths = Config::config_search_paths(None);
        assert!(paths.iter().any(|p| p == &PathBuf::from("config.json")));
    }

    #[test]
    fn default_config_all_rules_enabled() {
        let config = Config::default();
        assert!(config.enabled);
        assert!(config.rules.sensitive_file);
        assert!(config.rules.biome);
    }

    #[test]
    fn default_severity_blocks_critical_and_high() {
        let config = Config::default();
        assert!(config.severity.block_on.contains(&Severity::Critical));
        assert!(config.severity.block_on.contains(&Severity::High));
        assert!(!config.severity.block_on.contains(&Severity::Medium));
    }
}
