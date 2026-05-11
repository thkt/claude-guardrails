use crate::envelope::ErrorCode;
use crate::resolve::run_with_timeout;
use std::env;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const OXLINT_VERSION: &str = "1.56.0";

const DOWNLOAD_BASE: &str = "https://github.com/oxc-project/oxc/releases/download";

#[derive(Debug)]
pub enum OxlintError {
    CacheDirUnavailable,
    UnsupportedPlatform {
        os: &'static str,
        arch: &'static str,
    },
    NetworkFailure(String),
    ExtractFailure(String),
}

impl OxlintError {
    pub fn classify(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::UnsupportedPlatform { .. } => (
                ErrorCode::DataError,
                "Install oxlint manually via npm install -g oxlint",
            ),
            Self::NetworkFailure(_) => (
                ErrorCode::IoError,
                "Check network connectivity or install oxlint manually via npm",
            ),
            Self::ExtractFailure(_) => (
                ErrorCode::IoError,
                "Check disk space and filesystem permissions in the cache dir",
            ),
            Self::CacheDirUnavailable => (
                ErrorCode::IoError,
                "Set XDG_CACHE_HOME or HOME environment variable",
            ),
        }
    }
}

impl fmt::Display for OxlintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CacheDirUnavailable => {
                write!(
                    f,
                    "no cache directory available (set XDG_CACHE_HOME or HOME)"
                )
            }
            Self::UnsupportedPlatform { os, arch } => {
                write!(
                    f,
                    "unsupported platform for oxlint download (os={os}, arch={arch})"
                )
            }
            Self::NetworkFailure(e) => write!(f, "oxlint download failed: {e}"),
            Self::ExtractFailure(e) => write!(f, "oxlint extract failed: {e}"),
        }
    }
}

fn detect_platform() -> Option<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

fn download_url(version: &str, platform: &str) -> String {
    format!("{DOWNLOAD_BASE}/apps_v{version}/oxlint-{platform}.tar.gz")
}

fn default_cache_dir() -> Option<PathBuf> {
    let cache_base = env::var("XDG_CACHE_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cache"))
        })?;
    Some(cache_base.join("guardrails/bin"))
}

pub fn ensure_oxlint() -> Result<PathBuf, OxlintError> {
    let cache = default_cache_dir().ok_or(OxlintError::CacheDirUnavailable)?;
    ensure_oxlint_with(&cache, fetch_url)
}

fn ensure_oxlint_with<F>(cache: &Path, fetch: F) -> Result<PathBuf, OxlintError>
where
    F: FnOnce(&str) -> Result<Vec<u8>, OxlintError>,
{
    let version = OXLINT_VERSION;
    let target = cache.join(format!("oxlint-{version}"));

    if target.exists() {
        return Ok(target);
    }

    let platform = detect_platform().ok_or(OxlintError::UnsupportedPlatform {
        os: env::consts::OS,
        arch: env::consts::ARCH,
    })?;

    let url = download_url(version, platform);
    let bytes = fetch(&url)?;
    extract_to_cache(&bytes, cache, version)
}

const MAX_DOWNLOAD_SIZE: u64 = 50_000_000;

fn fetch_url(url: &str) -> Result<Vec<u8>, OxlintError> {
    eprintln!("guardrails: downloading oxlint v{OXLINT_VERSION}...");
    let resp = ureq::get(url)
        .call()
        .map_err(|e| OxlintError::NetworkFailure(e.to_string()))?;

    let mut bytes = Vec::new();
    resp.into_body()
        .into_reader()
        .take(MAX_DOWNLOAD_SIZE)
        .read_to_end(&mut bytes)
        .map_err(|e| OxlintError::NetworkFailure(e.to_string()))?;
    Ok(bytes)
}

fn extract_to_cache(bytes: &[u8], cache: &Path, version: &str) -> Result<PathBuf, OxlintError> {
    fs::create_dir_all(cache).map_err(|e| {
        OxlintError::ExtractFailure(format!(
            "failed to create cache dir {}: {e}",
            cache.display()
        ))
    })?;

    let tar_path = cache.join(format!("oxlint-{version}.tar.gz"));
    let target = cache.join(format!("oxlint-{version}"));

    fs::write(&tar_path, bytes).map_err(|e| {
        OxlintError::ExtractFailure(format!(
            "failed to write archive {}: {e}",
            tar_path.display()
        ))
    })?;

    let output = run_with_timeout(
        Command::new("tar")
            .args(["xzf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(cache),
        "tar",
    );

    let _ = fs::remove_file(&tar_path);

    let output = output.ok_or_else(|| {
        OxlintError::ExtractFailure(String::from("tar invocation failed or timed out"))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OxlintError::ExtractFailure(format!(
            "tar exited non-zero: {stderr}"
        )));
    }

    let extracted = cache.join("oxlint");
    if extracted != target {
        fs::rename(&extracted, &target).map_err(|e| {
            let _ = fs::remove_file(&extracted);
            OxlintError::ExtractFailure(format!("failed to rename oxlint binary: {e}"))
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&target, fs::Permissions::from_mode(0o755)) {
            eprintln!("guardrails: warning: failed to set executable permission: {e}");
        }
    }

    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // T-014: platform detection on supported OS
    #[test]
    fn detect_platform_returns_known_triple() {
        let platform = detect_platform();
        assert!(platform.is_some(), "expected Some on macOS/Linux");
        let p = platform.unwrap();
        assert!(
            [
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu"
            ]
            .contains(&p),
            "unexpected platform: {p}"
        );
    }

    // T-014: darwin-arm64 URL construction
    #[test]
    fn download_url_darwin_arm64_has_correct_format() {
        assert_eq!(
            download_url("1.56.0", "aarch64-apple-darwin"),
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.56.0/oxlint-aarch64-apple-darwin.tar.gz"
        );
    }

    // T-015: linux-x64 URL construction
    #[test]
    fn download_url_linux_x64_has_correct_format() {
        assert_eq!(
            download_url("1.56.0", "x86_64-unknown-linux-gnu"),
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.56.0/oxlint-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn default_cache_dir_ends_with_guardrails_bin() {
        let dir = default_cache_dir();
        assert!(dir.is_some());
        assert!(dir.unwrap().ends_with("guardrails/bin"));
    }

    // T-003: cached binary exists → return without download
    #[test]
    fn returns_cached_binary() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join(format!("oxlint-{OXLINT_VERSION}"));
        fs::write(&bin, "fake").unwrap();

        let result = ensure_oxlint_with(tmp.path(), |_| panic!("should not download"));
        assert_eq!(result.unwrap(), bin);
    }

    // T-005: network failure → NetworkFailure error
    #[test]
    fn returns_network_failure_on_fetch_error() {
        let tmp = TempDir::new().unwrap();
        let result = ensure_oxlint_with(tmp.path(), |_| {
            Err(OxlintError::NetworkFailure(String::from(
                "simulated DNS error",
            )))
        });
        assert!(matches!(result, Err(OxlintError::NetworkFailure(_))));
    }

    // T-004: download + extract + cache
    #[test]
    fn downloads_extracts_and_caches() {
        let tmp = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();

        let dummy = staging.path().join("oxlint");
        fs::write(&dummy, "#!/bin/sh\necho test").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dummy, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let tar = staging.path().join("test.tar.gz");
        assert!(Command::new("tar")
            .args(["czf"])
            .arg(&tar)
            .arg("-C")
            .arg(staging.path())
            .arg("oxlint")
            .status()
            .unwrap()
            .success());
        let tar_bytes = fs::read(&tar).unwrap();

        let result = ensure_oxlint_with(tmp.path(), |_| Ok(tar_bytes));
        let cached = result.unwrap();
        assert!(cached.exists());
        assert!(
            cached
                .to_str()
                .unwrap()
                .contains(&format!("oxlint-{OXLINT_VERSION}")),
            "cached path should contain versioned name"
        );
    }
}
