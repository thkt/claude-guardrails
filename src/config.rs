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
    #[serde(default = "default_true")]
    pub architecture: bool,
    #[serde(rename = "errorHandling", default = "default_true")]
    pub error_handling: bool,
    #[serde(default = "default_true")]
    pub naming: bool,
    #[serde(default = "default_true")]
    pub transaction: bool,
    #[serde(rename = "consoleLog", default = "default_true")]
    pub console_log: bool,
    #[serde(default = "default_true")]
    pub security: bool,
    #[serde(default = "default_true")]
    pub biome: bool,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            architecture: true,
            error_handling: true,
            naming: true,
            transaction: true,
            console_log: true,
            security: true,
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
                eprintln!("guardrails: warning: cannot read config {:?}: {}", config_path, e);
                Config::default()
            }
        }
    }

    fn config_path() -> PathBuf {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let mut search_paths = Vec::new();

        if let Some(dir) = exe_dir {
            search_paths.push(dir.join("../../config.json"));
            search_paths.push(dir.join("../config.json"));
            search_paths.push(dir.join("config.json"));
        }

        // Fallback: current directory
        search_paths.push(PathBuf::from("config.json"));

        // Fallback: XDG config home or ~/.config
        if let Some(config_dir) = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        {
            search_paths.push(config_dir.join("guardrails/config.json"));
        }

        search_paths
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_default()
    }
}
