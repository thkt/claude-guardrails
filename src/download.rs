use crate::envelope::ErrorCode;
use constant_time_eq::constant_time_eq;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::env;
use std::fmt;
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

#[derive(Debug)]
pub enum OxlintError {
    CacheDirUnavailable,
    UnsupportedPlatform {
        os: &'static str,
        arch: &'static str,
    },
    NetworkFailure(String),
    ChecksumMismatch {
        expected: String,
        actual: String,
    },
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
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "oxlint tarball SHA-256 mismatch: expected {expected}, got {actual}"
            ),
            Self::ExtractFailure(e) => write!(f, "oxlint extract failed: {e}"),
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
    // Set executable bit before persist so the rename publishes a binary that
    // is already 0o755. Avoids a window where a parallel ensure_oxlint sees
    // target.exists() and returns a path that is not yet chmod'd.
    set_executable_on(tmp.as_file_mut())?;
    tmp.as_file_mut().sync_all().map_err(|e| map_io_err(&e))?;
    tmp.persist(target).map_err(|e| {
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
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;
    use tempfile::TempDir;

    fn make_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = Builder::new(gz);
            for (name, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar.append(&header, *content).unwrap();
            }
            tar.into_inner().unwrap().finish().unwrap();
        }
        buf
    }

    fn make_signed_tar(platform: &str, content: &[u8]) -> Vec<u8> {
        let name = format!("oxlint-{platform}");
        make_tar_gz(&[(name.as_str(), content)])
    }

    // `tar::Header::set_path` refuses `..`; this helper bypasses that to forge
    // an archive that mimics the attacker tarball case the validator must reject.
    fn make_evil_tar(raw_name: &[u8], content: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = Builder::new(gz);
            let mut header = tar::Header::new_old();
            let slot = &mut header.as_old_mut().name;
            let n = raw_name.len().min(slot.len());
            slot[..n].copy_from_slice(&raw_name[..n]);
            header.set_mode(0o644);
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append(&header, content).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        buf
    }

    fn checksum_of(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    // T-014: platform detection on supported OS
    #[test]
    fn detect_pin_returns_known_triple() {
        let pin = detect_pin().expect("expected Some on macOS/Linux");
        assert!(
            [
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu"
            ]
            .contains(&pin.triple),
            "unexpected platform: {}",
            pin.triple
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

    #[test]
    fn pinned_checksum_table_is_well_formed() {
        for expected in [
            ("macos", "aarch64"),
            ("macos", "x86_64"),
            ("linux", "x86_64"),
            ("linux", "aarch64"),
        ] {
            assert!(
                PLATFORMS.iter().any(|(o, a, _)| (*o, *a) == expected),
                "missing pin for {expected:?}"
            );
        }
        for (_, _, pin) in PLATFORMS {
            assert_eq!(
                pin.sha256.len(),
                64,
                "pin for {} must be 32 bytes hex",
                pin.triple
            );
            assert!(
                pin.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "pin for {} must be hex",
                pin.triple
            );
        }
    }

    #[test]
    fn hex_round_trip_preserves_bytes() {
        let bytes: Vec<u8> = (0..=255).collect();
        let encoded = encode_hex(&bytes);
        assert_eq!(encoded.len(), bytes.len() * 2);
        assert_eq!(decode_hex(&encoded).unwrap(), bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn validate_entry_path_rejects_parent_traversal() {
        let err = validate_entry_path(Path::new("../escape")).unwrap_err();
        assert!(
            matches!(err, OxlintError::ExtractFailure(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn validate_entry_path_rejects_absolute() {
        let err = validate_entry_path(Path::new("/etc/passwd")).unwrap_err();
        assert!(matches!(err, OxlintError::ExtractFailure(_)));
    }

    #[test]
    fn validate_entry_path_accepts_simple_filename() {
        validate_entry_path(Path::new("oxlint-aarch64-apple-darwin")).unwrap();
    }

    #[test]
    fn extract_rejects_tarball_with_checksum_mismatch() {
        let tmp = TempDir::new().unwrap();
        let tar = make_signed_tar("aarch64-apple-darwin", b"fake oxlint payload");
        let bogus_pin = "a".repeat(64);
        let err = extract_to_cache(
            &tar,
            &bogus_pin,
            tmp.path(),
            OXLINT_VERSION,
            "aarch64-apple-darwin",
        )
        .unwrap_err();
        assert!(
            matches!(err, OxlintError::ChecksumMismatch { .. }),
            "expected ChecksumMismatch, got {err:?}"
        );
    }

    #[test]
    fn extract_writes_binary_when_checksum_matches() {
        let tmp = TempDir::new().unwrap();
        let payload = b"#!/bin/sh\necho test\n";
        let platform = "aarch64-apple-darwin";
        let tar = make_signed_tar(platform, payload);
        let pin = encode_hex(&checksum_of(&tar));

        let target = extract_to_cache(&tar, &pin, tmp.path(), OXLINT_VERSION, platform).unwrap();

        assert_eq!(target, tmp.path().join(format!("oxlint-{OXLINT_VERSION}")));
        assert_eq!(fs::read(&target).unwrap(), payload);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "expected 0o755, got {mode:o}");
        }
    }

    #[test]
    fn extract_rejects_tarball_with_path_traversal_entry() {
        let tmp = TempDir::new().unwrap();
        let payload = b"escape attempt";
        let tar = make_evil_tar(b"../etc/passwd", payload);
        let pin = encode_hex(&checksum_of(&tar));

        let err = extract_to_cache(
            &tar,
            &pin,
            tmp.path(),
            OXLINT_VERSION,
            "aarch64-apple-darwin",
        )
        .unwrap_err();
        match err {
            OxlintError::ExtractFailure(msg) => {
                assert!(
                    msg.contains("unsafe path") || msg.contains("absolute path"),
                    "msg: {msg}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !tmp.path().parent().unwrap().join("etc/passwd").exists(),
            "path traversal must not write outside cache"
        );
    }

    #[test]
    fn extract_rejects_tarball_with_absolute_path_entry() {
        let tmp = TempDir::new().unwrap();
        let tar = make_evil_tar(b"/etc/passwd", b"hostile");
        let pin = encode_hex(&checksum_of(&tar));

        let err = extract_to_cache(
            &tar,
            &pin,
            tmp.path(),
            OXLINT_VERSION,
            "aarch64-apple-darwin",
        )
        .unwrap_err();
        match err {
            OxlintError::ExtractFailure(msg) => {
                assert!(msg.contains("absolute path"), "msg: {msg}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parallel_extracts_converge_on_single_binary() {
        use std::sync::Arc;
        use std::thread;

        let tmp = TempDir::new().unwrap();
        let payload = vec![0x42_u8; 4096];
        let platform = "aarch64-apple-darwin";
        let tar = Arc::new(make_signed_tar(platform, &payload));
        let pin = Arc::new(encode_hex(&checksum_of(&tar)));
        let cache = Arc::new(tmp.path().to_path_buf());

        let mut handles = Vec::new();
        for _ in 0..8 {
            let tar = Arc::clone(&tar);
            let pin = Arc::clone(&pin);
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                extract_to_cache(&tar, &pin, &cache, OXLINT_VERSION, platform)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first = results[0]
            .as_ref()
            .expect("at least one extract must succeed");
        for r in &results {
            let p = r.as_ref().expect("every parallel extract must succeed");
            assert_eq!(p, first, "all threads converge on the same target path");
        }
        assert_eq!(
            fs::read(first).unwrap(),
            payload,
            "final binary must match payload bit-for-bit"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(first).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o755,
                "binary published via rename must already have 0o755 (no chmod-after-persist window)"
            );
        }
        let leftover: Vec<_> = fs::read_dir(cache.as_path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            leftover.len(),
            1,
            "no orphan temp files allowed; got: {leftover:?}"
        );
    }

    #[test]
    fn extract_rejects_tarball_missing_expected_entry() {
        let tmp = TempDir::new().unwrap();
        let tar = make_tar_gz(&[("oxlint-other-platform", b"oops")]);
        let pin = encode_hex(&checksum_of(&tar));

        let err = extract_to_cache(
            &tar,
            &pin,
            tmp.path(),
            OXLINT_VERSION,
            "aarch64-apple-darwin",
        )
        .unwrap_err();
        match err {
            OxlintError::ExtractFailure(msg) => {
                assert!(msg.contains("not found"), "msg: {msg}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
