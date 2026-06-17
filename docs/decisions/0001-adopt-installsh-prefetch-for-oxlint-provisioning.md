---
status: "accepted"
date: 2026-05-08
decision-makers: thkt
---

# Adopt install.sh prefetch for oxlint provisioning

## Context and Problem Statement

guardrails resolves `oxlint` lazily at hook fire time via a 4-step chain (`node_modules/.bin` → `PATH` → `~/.cache/guardrails/bin/oxlint-{version}` → GitHub Releases auto-download → fail-open to custom rules only). This makes the _first_ `Write`/`Edit` after install pay the download latency, which feels rough. Should we change the distribution form to eliminate that first-run cost?

## Decision Drivers

- First-run UX: the initial Write/Edit should not stall on a download
- Maintenance cost: avoid coupling guardrails releases to upstream oxlint cadence
- Build/dependency footprint: keep guardrails' own crate graph and binary size lean
- Reversibility: prefer the option whose rollback is one-line removal

## Considered Options

- `install.sh` prefetch + `guardrails prefetch` subcommand
- Bundle the oxlint binary into release tarballs
- Embed `oxc_linter` as a Cargo dependency (in-process linting)
- Status quo (lazy resolve only)

## Decision Outcome

Chosen option: **`install.sh` prefetch + `guardrails prefetch` subcommand**, because it shifts the download to the install moment (where downloads are already happening) without touching the distribution form, while exposing a manual hook (`prefetch`) that doubles as a CI-cache and air-gap pre-stage tool.

### Consequences

- Good, because first-run Write/Edit no longer waits on a download
- Good, because the existing 4-step resolve chain stays untouched (rollback = remove one line from `install.sh`)
- Good, because `prefetch` is reusable for CI warm-up and offline pre-stage
- Bad, because `install.sh` now requires network at install time (acceptable: guardrails itself is being downloaded right then)
- Bad, because new `prefetch` subcommand adds a small surface to test

### Confirmation

This ADR is implemented across two repositories. The split is dictated by where the relevant artifacts live, not by ADR scope.

**In `thkt/guardrails` (this repo)**

- `tests/cli/prefetch.rs` (`prefetch_returns_zero_when_oxlint_already_cached`) covers `guardrails prefetch` for the success path (cached binary present)
- The offline graceful-failure path is exercised at the install layer (the `|| true` guard in sentinels) and is verified manually rather than in CI

**In `thkt/sentinels` (plugin distribution, tracked in thkt/sentinels#4)**

- End-to-end test verifies oxlint cache exists at `~/.cache/guardrails/bin/oxlint-{version}` after install
- Manual: fresh install on a clean machine, confirm the first `Write` triggers no network activity

## Pros and Cons of the Options

### `install.sh` prefetch + `guardrails prefetch` subcommand

Run the existing download path eagerly during plugin install; expose it as a subcommand for manual reuse.

- Good, because zero impact on distribution artifacts (tarball / brew formula / `Cargo.toml` unchanged)
- Good, because subcommand is a thin wrapper over `download.rs` — minimal new code
- Good, because `|| true` in the install script keeps offline installs working (degrades to current lazy behavior)
- Bad, because oxlint version bumps still re-download on next hook fire (same as today)

### Bundle the oxlint binary into release tarballs

Ship oxlint alongside the guardrails binary in each platform-specific release artifact.

- Good, because eliminates the first-run download entirely
- Bad, because requires per-platform/per-arch build matrix expansion
- Bad, because every oxlint release forces a guardrails re-release to stay current
- Bad, because tarball size grows substantially
- Bad, because effective benefit over `install.sh` prefetch is "install fails offline → first hook fails offline" — marginal

### Embed `oxc_linter` as a Cargo dependency

Replace the external oxlint process with in-process linting via the `oxc_linter` crate.

- Good, because single binary, no subprocess overhead
- Bad, because `oxc_linter/Cargo.toml` declares `publish = false` — crates.io returns 404
- Bad, because git/path dependency only → API churn (CHANGELOG.md is 327 KB) breaks guardrails on every internal refactor
- Bad, because pulls in ~20 internal `oxc_*` crates plus heavy transitive deps → guardrails build time and binary size balloon
- Bad, because directly contradicts upstream's "do not depend on this as a library" signal

### Status quo (lazy resolve only)

Keep the current 4-step resolve chain unchanged.

- Good, because zero new code
- Bad, because the original UX complaint is unaddressed

## More Information

### Implementation Plan

This ADR is implemented across two repositories.

**In `thkt/guardrails` (this repo)**

1. Add `prefetch` subcommand to `src/main.rs` — thin wrapper around the existing function in `src/download.rs`
2. Add integration test in `tests/cli/prefetch.rs` (`prefetch_returns_zero_when_oxlint_already_cached`) covering the success path (cached binary present)
3. Document `guardrails prefetch` in README under "Requirements"

**In `thkt/sentinels` (plugin distribution, tracked in thkt/sentinels#4)**

1. Append `"$BIN_DIR/guardrails" prefetch || true` to the install routine — likely `shared/hooks/install-lib.sh` (`install_tool` function tail) so all tools benefit, or `guardrails/hooks/install.sh` if guardrails-specific. The `|| true` keeps offline installs from failing
2. End-to-end verification that the oxlint cache exists post-install

### Rollback Plan

Remove the appended line from the install routine in sentinels. The `prefetch` subcommand in this repo can stay as an opt-in utility even if the auto-trigger is reverted.

### Reassessment Triggers

- If oxlint upstream publishes `oxc_linter` to crates.io with a stable library API → re-evaluate the embed option
- If oxlint binary stabilizes on a long-term version → reconsider bundling once update churn drops

### References

- `README.md:84-93` — current oxlint resolution order
- `src/resolve.rs`, `src/download.rs` — existing auto-provision implementation
- `crates/oxc_linter/Cargo.toml:11` (oxc-project/oxc) — `publish = false`
- `https://crates.io/crates/oxc_linter` — confirmed 404
