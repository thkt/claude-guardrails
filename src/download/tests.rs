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
