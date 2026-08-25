use crate::content::length_within_cap;
use crate::io::envelope::ErrorCode;
use constant_time_eq::constant_time_eq;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Component, Path, PathBuf};
use tar::Archive;
use tempfile::NamedTempFile;

const OXLINT_VERSION: &str = "1.56.0";

const DOWNLOAD_BASE: &str = "https://github.com/oxc-project/oxc/releases/download";

struct PlatformPin {
    triple: &'static str,
    sha256: &'static str,
}

// Platform pin table. One entry per (OS, ARCH) we support. `sha256` is the
// SHA-256 of the upstream tarball; regenerate all entries on OXLINT_VERSION
// bump via `shasum -a 256 oxlint-<triple>.tar.gz` against the release artifacts.
const PLATFORMS: &[(&str, &str, PlatformPin)] = &[
    (
        "macos",
        "aarch64",
        PlatformPin {
            triple: "aarch64-apple-darwin",
            sha256: "7915dc73c905c6489608cc3dc844556342b17f6599b2e7e9a0dd9bf0e7fa6341",
        },
    ),
    (
        "macos",
        "x86_64",
        PlatformPin {
            triple: "x86_64-apple-darwin",
            sha256: "9c035c431032c7038b2763474da73a18c476d41320eb455680f5b46f3dc52a9f",
        },
    ),
    (
        "linux",
        "x86_64",
        PlatformPin {
            triple: "x86_64-unknown-linux-gnu",
            sha256: "487d00ac3c609c9020abbd879a91c183560dc382e15356be2a1bd6d860ed952f",
        },
    ),
    (
        "linux",
        "aarch64",
        PlatformPin {
            triple: "aarch64-unknown-linux-gnu",
            sha256: "f0c3f2895204c97d2aedeb62db6913e4ac186ab94c1dd4b9812a35223039d6f5",
        },
    ),
];

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum OxlintError {
    #[error("no cache directory available (set XDG_CACHE_HOME or HOME)")]
    CacheDirUnavailable,
    #[error("unsupported platform for oxlint download (os={os}, arch={arch})")]
    UnsupportedPlatform {
        os: &'static str,
        arch: &'static str,
    },
    #[error("oxlint download failed: {0}")]
    NetworkFailure(String),
    #[error("oxlint download exceeds {cap}-byte size limit")]
    DownloadTooLarge { cap: u64 },
    #[error("oxlint tarball SHA-256 mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("oxlint extract failed: {0}")]
    ExtractFailure(String),
}

impl OxlintError {
    pub(crate) fn classify(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::UnsupportedPlatform { .. } => (
                ErrorCode::DataError,
                "Install oxlint manually via npm install -g oxlint",
            ),
            Self::NetworkFailure(_) => (
                ErrorCode::IoError,
                "Check network connectivity or install oxlint manually via npm",
            ),
            Self::DownloadTooLarge { .. } => (
                ErrorCode::DataError,
                "oxlint release exceeds the size limit; install oxlint manually via npm install -g oxlint",
            ),
            Self::ChecksumMismatch { .. } => (
                ErrorCode::IoError,
                "Re-download or install oxlint manually via npm install -g oxlint",
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

fn detect_pin() -> Option<&'static PlatformPin> {
    PLATFORMS.iter().find_map(|(os, arch, pin)| {
        (*os == env::consts::OS && *arch == env::consts::ARCH).then_some(pin)
    })
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

pub(crate) fn ensure_oxlint() -> Result<PathBuf, OxlintError> {
    let cache = default_cache_dir().ok_or(OxlintError::CacheDirUnavailable)?;
    ensure_oxlint_with(&cache, fetch_url)
}

fn ensure_oxlint_with<F>(cache: &Path, fetch: F) -> Result<PathBuf, OxlintError>
where
    F: FnOnce(&str) -> Result<Vec<u8>, OxlintError>,
{
    let version = OXLINT_VERSION;
    let target = cache.join(format!("oxlint-{version}"));

    // Trust-on-first-write: cache hit skips SHA re-verification because
    // `extract_to_cache` only ever persists a `write_atomic`-renamed entry
    // after a successful SHA check, so anything already at `target` came
    // through that path. Keeps hook startup off the verify hot path.
    if target.exists() {
        return Ok(target);
    }

    let pin = detect_pin().ok_or(OxlintError::UnsupportedPlatform {
        os: env::consts::OS,
        arch: env::consts::ARCH,
    })?;

    let url = download_url(version, pin.triple);
    let bytes = fetch(&url)?;
    extract_to_cache(&bytes, pin.sha256, cache, version, pin.triple)
}

const MAX_DOWNLOAD_SIZE: u64 = 50_000_000;

fn fetch_url(url: &str) -> Result<Vec<u8>, OxlintError> {
    eprintln!("guardrails: downloading oxlint v{OXLINT_VERSION}...");
    // Integrity rests solely on the SHA-256 pin (verify_sha256, constant-time):
    // bytes off any host fail the pin and never execute. Redirects are followed
    // by default because the GitHub release asset 302s to
    // objects.githubusercontent.com; pinning the scheme/host would reject that
    // legitimate hop and break cold-cache install on every platform.
    let resp = ureq::get(url)
        .call()
        .map_err(|e| OxlintError::NetworkFailure(e.to_string()))?;

    let mut reader = resp.into_body().into_reader();
    read_capped(&mut reader, MAX_DOWNLOAD_SIZE)
}

// Read at most `cap` bytes, rejecting anything larger as DownloadTooLarge.
// Reading `cap + 1` then checking the length distinguishes an exactly-`cap`
// legit file from a larger one truncated to `cap` (which would otherwise read
// back clean and fail SHA later as a misleading ChecksumMismatch, #310).
fn read_capped(reader: &mut dyn Read, cap: u64) -> Result<Vec<u8>, OxlintError> {
    let mut bytes = Vec::new();
    reader
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| OxlintError::NetworkFailure(e.to_string()))?;
    if !length_within_cap(bytes.len(), cap) {
        return Err(OxlintError::DownloadTooLarge { cap });
    }
    Ok(bytes)
}

fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), OxlintError> {
    let expected = decode_hex(expected_hex).map_err(OxlintError::ExtractFailure)?;

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hasher.finalize();

    if constant_time_eq(actual.as_slice(), &expected) {
        return Ok(());
    }
    Err(OxlintError::ChecksumMismatch {
        expected: expected_hex.to_owned(),
        actual: encode_hex(&actual),
    })
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("invalid hex length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex byte: {e}")))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn validate_entry_path(path: &Path) -> Result<(), OxlintError> {
    if path.is_absolute() {
        return Err(OxlintError::ExtractFailure(format!(
            "absolute path rejected in archive entry: {}",
            path.display()
        )));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(OxlintError::ExtractFailure(format!(
                "unsafe path component rejected in archive entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn extract_to_cache(
    bytes: &[u8],
    expected_sha_hex: &str,
    cache: &Path,
    version: &str,
    platform: &str,
) -> Result<PathBuf, OxlintError> {
    verify_sha256(bytes, expected_sha_hex)?;

    fs::create_dir_all(cache).map_err(|e| {
        OxlintError::ExtractFailure(format!(
            "failed to create cache dir {}: {e}",
            cache.display()
        ))
    })?;

    let target = cache.join(format!("oxlint-{version}"));
    let expected_entry = format!("oxlint-{platform}");

    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(gz);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

    let entries = archive.entries().map_err(|e| map_io_err(&e))?;
    let mut wrote_binary = false;
    for entry in entries {
        let mut entry = entry.map_err(|e| map_io_err(&e))?;
        let entry_path = entry.path().map_err(|e| map_io_err(&e))?.into_owned();
        validate_entry_path(&entry_path)?;

        if entry_path != Path::new(&expected_entry) {
            continue;
        }

        write_atomic(&mut entry, cache, &target)?;
        wrote_binary = true;
        break;
    }

    if !wrote_binary {
        return Err(OxlintError::ExtractFailure(format!(
            "expected archive entry {expected_entry} not found"
        )));
    }

    Ok(target)
}

fn write_atomic<R: Read>(reader: &mut R, cache: &Path, target: &Path) -> Result<(), OxlintError> {
    let mut tmp = NamedTempFile::new_in(cache).map_err(|e| {
        OxlintError::ExtractFailure(format!(
            "failed to create temp file in {}: {e}",
            cache.display()
        ))
    })?;
    io::copy(reader, tmp.as_file_mut()).map_err(|e| map_io_err(&e))?;
    // `ensure_oxlint` hands back `target` the instant the rename lands, so a
    // parallel process sees whatever is not finished by then: a path not yet
    // 0o755, or one whose still-open write fd makes exec fail with ETXTBSY
    // (#470, Linux only; macOS never raises it). Hence not
    // `NamedTempFile::persist`, which renames first and returns the file still
    // open (tempfile 3.27.0 `file/mod.rs:767`).
    set_executable_on(tmp.as_file_mut())?;
    tmp.as_file_mut().sync_all().map_err(|e| map_io_err(&e))?;
    tmp.into_temp_path().persist(target).map_err(|e| {
        OxlintError::ExtractFailure(format!(
            "failed to persist binary to {}: {e}",
            target.display()
        ))
    })?;
    Ok(())
}

fn map_io_err(e: &io::Error) -> OxlintError {
    OxlintError::ExtractFailure(e.to_string())
}

fn set_executable_on(file: &mut fs::File) -> Result<(), OxlintError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|e| map_io_err(&e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
