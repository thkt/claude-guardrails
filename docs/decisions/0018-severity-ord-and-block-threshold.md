---
status: "accepted"
date: 2026-05-26
decision-makers: thkt
---

# Introduce `Ord` on `Severity` and replace the `block_on` set with `block_threshold`

## Context and Problem Statement

`Severity` in `src/rules/mod.rs` (`Critical` / `High` / `Medium` / `Low`) did not derive `Ord`, and the blocking decision was made by set membership over `SeverityConfig.block_on: Vec<Severity>` (`block_on.contains(&v.severity)`). The default was `block_on = [Critical, High]`.

This set representation is semantically weak.

1. **Non-monotonic configs type-check.** `block_on = [Critical, Medium]` ("block Critical, do not block High, block Medium") is accepted with no validation. The set permits configurations that are nonsensical given what severity means.
2. **The ordering of `Severity` is not expressed in the type.** The names strongly imply `Critical > High > Medium > Low`, yet `Severity::High < Severity::Critical` is not comparable at the type level.
3. **The state space is needlessly large.** For four severity values only five thresholds are meaningful (none / critical+ / high+ / medium+ / low+), but a set allows 2^4 = 16 combinations.

## Decision Drivers

- Make non-monotonic blocking configs unrepresentable at the type level.
- Surface the total order inherent to `Severity` in the type, and express the blocking decision as a single "at or above" comparison.
- Give users an intuitive config shape (`"blockThreshold": "high"`).
- Stay consistent with ADR-0006 (config migration policy): emit no deprecation warnings (avoid polluting hook output).

## Considered Options

- **A. `block_threshold: Severity` + `Severity: Ord` (chosen)**: replace the set with a single threshold; "block at or above the threshold".
- B. `block_threshold: Option<Severity>` (None = block nothing): preserve the block-none capability.
- C. Keep `block_on`, add runtime validation that rejects non-monotonic sets.
- D. Backward-compatible conversion: read the old `blockOn` and alias it to a threshold (e.g. its minimum element).

## Decision Outcome

Chosen: **Option A**.

- Reverse the declaration order of `Severity` to `Low, Medium, High, Critical` and derive `PartialOrd, Ord` (derived `Ord` follows declaration order, so `Critical` is the maximum).
- Replace `SeverityConfig.block_on: Vec<Severity>` with `block_threshold: Severity`, default `Severity::High` (equivalent to the old `[Critical, High]`).
- `partition_violations` splits blocking from warning with `v.severity >= config.severity.block_threshold`.
- The config DTO renames `blockOn` to `blockThreshold`.

Rationale:

- B (preserve block-none via `Option`) is rejected. Block-none is undocumented, has no usage examples, and was not requested. Making `Option<Severity>`'s `None` reachable from config would require an `Option<Option<Severity>>` DTO plus null semantics — needless complexity (YAGNI). It can be reintroduced cheaply later (see Reversibility).
- C (validation) pushes an invariant that the type can express down into a runtime check; rejected.
- D (backward-compatible conversion) is rejected. The set-to-threshold conversion rule (minimum element? contiguity check?) is non-obvious, and converting a non-monotonic set is ambiguous. Pre-1.0 (v0.x) permits the breaking change.

### Scope

Breaking change (config schema): `severity.blockOn` (an array) is removed and replaced by `severity.blockThreshold` (a single severity). Lands in v0.17.0.

Classification of old configs whose behavior changes:

| Old `blockOn` | New behavior |
| --- | --- |
| `[critical, high]` (old default) | Equivalent to the new default `high`. **No change.** |
| Set containing `medium` / `low` | That severity is demoted from blocking to advisory. Must migrate to `"blockThreshold": "medium"` etc. |
| `[]` (block-none) | Becomes the new default `high`. **No equivalent** (capability removed). |
| Non-monotonic set (`[critical, medium]` etc.) | Becomes the new default `high`. Invalid by this ADR's argument anyway. |

### Why not `deny_unknown_fields`

Adding `#[serde(deny_unknown_fields)]` to `ProjectSeverityConfig` would turn an old `blockOn` into a parse error and make the break "loud", but we do not do this.

- **Atomicity**: `severity` is one field of `ProjectConfig`, so a single stale `blockOn` fails the entire `ProjectConfig` parse, and fail-open then discards the user's `rules` / `oxlint` overrides too (ADR-0004). The blast radius exceeds what the user intended to break.
- **ADR-0006 consistency**: aligns with the no-deprecation-warning policy.
- **Symmetry with other config structs**: every other `ProjectXxxConfig` silently ignores unknown fields. Do not make severity asymmetric.
- The harm of silent ignore is bounded: users on the old default `[critical, high]` see no behavior change. Only non-standard configs that explicitly listed `medium`/`low` are demoted, and the README documents the migration.

## Consequences

### Positive

- Non-monotonic blocking configs become unrepresentable at the type level.
- The blocking decision collapses to a single `>=` comparison, and the state space shrinks from 16 to 5 (effectively 4: block-none removed).
- The config is intuitive: `"blockThreshold": "high"`.

### Negative

- Breaking config-schema change. Old `blockOn` configs silently shift to the threshold (migration documented in the README).
- Block-none (advisory-only mode) becomes unrepresentable.

### Reversibility

If block-none is needed, reintroduce it as `block_threshold: Option<Severity>` with an `Option<Option<Severity>>` DTO plus null. Record that as an ADR superseding this one.

## Supersedes

This ADR replaces the `block_on` membership mechanism described in ADR-0003 / 0004 / 0005. The substance of those decisions (math-random = Medium / fail-mode policy / envelope exit codes) is unchanged; only the mechanism description is updated here.
