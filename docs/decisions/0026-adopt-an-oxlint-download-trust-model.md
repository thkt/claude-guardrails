---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Anchor oxlint download integrity on the SHA-256 pin, not on transport or host

## Context and Problem Statement

guardrails fetches the oxlint binary at first use (`src/download.rs`) and executes it. The download path makes three security-load-bearing choices: what establishes integrity, when re-verification is skipped, and how an untrusted tarball is extracted. Each is recorded only as a local comment stating current behavior. A contributor "hardening" any one of them (pinning the host, re-verifying on every run, enabling tar metadata) would either break cold-cache install on every platform or open an unverified-execution hole, and no test states the trust model as a single contract.

## Decision Drivers

- A downloaded binary must never execute unless its bytes match the pinned hash.
- Cold-cache install must work on every platform without per-host allow-listing.
- Hook startup must stay off the verification hot path (NFR latency budget).
- Tarball extraction must not write outside the cache or carry attacker-controlled metadata.

## Considered Options

- **A. Pin scheme/host in addition to the hash**: rejects the legitimate GitHub release 302 to `objects.githubusercontent.com`, breaking cold install. The hash already makes transport untrusted-by-default, so host pinning adds no integrity.
- **B. Re-verify SHA on every cache hit**: puts a hash over a ~MB binary on the startup hot path for no gain, since only a verified entry is ever persisted.
- **C. Pin the trust model in one ADR (chosen)**: the hash is the sole root of trust; everything downstream derives from it.

## Decision Outcome

Chosen: **Option C**. The oxlint download trust model is the following three invariants, which must remain true unless superseded.

1. **The SHA-256 pin is the sole integrity check.** `fetch_url` (`src/download.rs:165`) follows redirects by default and does not pin scheme or host, because integrity rests entirely on `verify_sha256` (constant-time): bytes off any host fail the pin and never execute. Pinning the host would reject the GitHub asset's 302 hop and break cold install. The read is capped at `MAX_DOWNLOAD_SIZE` (50 MB) via `read_capped`, which reads `cap + 1` then length-checks so an oversize body fails as `DownloadTooLarge`, never as a misleading `ChecksumMismatch` (#310).
2. **Trust-on-first-write: a cache hit skips re-verification.** `ensure_oxlint` (`src/download.rs:145`) returns immediately when `target` exists, because `extract_to_cache` only ever persists a `write_atomic`-renamed entry after a passing SHA check. Anything already at `target` therefore came through verification. This invariant is load-bearing: a code path that writes the cache target without a prior SHA check turns the cache into an unverified-execution hole.
3. **Tarball extraction rejects unsafe paths and drops metadata.** `validate_entry_path` (`src/download.rs:231`) rejects absolute paths and any non-`Normal` component (path traversal), and extraction forces `preserve_permissions` / `mtime` / xattrs off, so an untrusted archive cannot escape the cache directory or carry attacker-controlled file metadata.

### Confirmation

Compliance is verified by reading the three call sites: integrity must flow through `verify_sha256` before any persist or execute, the cache-hit early return must have no write path that bypasses `extract_to_cache`, and tar extraction must keep `validate_entry_path` plus the metadata-off settings. Existing download tests exercise the cap-boundary (`DownloadTooLarge` vs `ChecksumMismatch`) and the path-traversal rejection; a change to the trust model must keep those green and update this ADR.

## Reversibility

Reversal is medium: the model spans `fetch_url`, `ensure_oxlint`, and `extract_to_cache` within one module, but changing it alters the install security posture and the cold-start contract, so it is a coordinated multi-function change, not a one-line edit.

## More Information

Consolidates census ADR-gap findings #11 (`download.rs:165-178`), #12 (`download.rs:146-151`), and #13 (`download.rs:231-247`) from `docs/audit/2026-06-30-071839-adr-gaps.md`. Distinct from ADR-0001 (install.sh prefetch provisioning), which covers the shell-side prefetch, not the in-binary download trust model.
