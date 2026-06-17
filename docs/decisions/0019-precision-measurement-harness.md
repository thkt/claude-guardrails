---
status: "accepted"
date: 2026-06-10
decision-makers: thkt
---

# Measure per-rule precision, recall, and latency with an in-source corpus harness

## Context and Problem Statement

The project outcome demands that violation-detection precision and the agent-facing experience improve continuously, yet nothing measures either. There is no corpus of known violations or near-misses, no false-positive tracking, and the `<10ms/file` latency assertion (`assert_under_10ms`) covers 4 of the 39 first-party rule_ids. Rule improvements land on gut feeling, and a precision regression would reach `main` undetected (Issue #255).

Three structural constraints shape any solution.

1. **Binary crate visibility.** guardrails has no `lib.rs`; integration tests under `tests/` can only spawn the binary. In-process access to the production pipeline (`hook::collect_violations`) is possible only from `#[cfg(test)]` modules inside `src/`.
2. **Self-hooking repository.** This repo runs guardrails as its own PreToolUse hook. Should-fire samples are, by definition, content the hook blocks (secrets, CoT markers, injection sinks). Editing such samples as Rust string literals in `src/` triggers the very rules they exercise. `tests/rule_smoke.rs` worked around this with per-fixture escaping (hex escapes, runtime `format!`), which does not scale to a corpus of 80+ samples.
3. **Toggle granularity is coarser than rule granularity.** `RulesConfig` exposes 27 toggles for 39 rule_ids; the `ast_security` toggle alone gates 13 rule_ids that always run together in production. A "latency per rule_id with only that rule enabled" measurement is unrepresentable for those 13.

## Decision Drivers

- Latency numbers must reflect the production pipeline (same parse, same dispatch), not a synthetic path.
- The corpus must follow the hook contract: one file content plus one file path per sample.
- The production binary must not grow: no corpus, no measurement code, no new runtime dependency (hook startup cost is a hard constraint).
- The CI gate must fail on false-positive regressions without blocking the workflow of banking known false negatives first and fixing them in later PRs.
- Fixture authoring must not fight the repo's own hook.

## Considered Options

- **A. Spawn harness in `tests/`**: drive the real binary with `--json` over a corpus, aggregate the envelope.
- **B. In-process harness in `src/` with inline fixtures**: call `collect_violations` from a `#[cfg(test)]` module; samples as Rust string literals.
- **C. External fixture tree with directory walk**: `corpus/` of real `.ts` files discovered at runtime, metadata in file headers or sidecars.
- **D. In-process harness + external fixture files via `include_str!` (chosen)**: harness as in B; sample bodies live in non-JS files under `src/hook/precision/fixtures/`, referenced at compile time; per-sample metadata (expected rule, virtual hook path, fire/clean expectation) stays in a Rust table.

## Decision Outcome

Chosen: **Option D**, as `#[cfg(test)] mod precision;` under `src/hook/` (a sibling of `src/hook/tests.rs`, which already calls `collect_violations` directly).

- A is rejected for latency semantics: per-file time disappears into process startup, so NFR-001 cannot be measured per rule, and the latency acceptance criterion would need a second, separate mechanism.
- B is rejected by the self-hook constraint: authoring 80+ violation literals inside `.rs` files means every corpus edit fights blocking rules; escaping each sample destroys the corpus's value as readable, realistic code.
- C is rejected for contract duplication: real `.ts` fixture paths would be both the hook-contract path and the filesystem path, forcing a metadata convention and walk logic the compiler gives us for free with `include_str!` (a missing fixture is a compile error, not a silent corpus hole).
- D keeps B's measurement fidelity and C's fixture readability. Fixture files use a non-JS extension, so the self-hook's AST rules never parse them on edit; only the few content-scanned samples (CoT marker, hardcoded secret, generated marker) need shell-based placement.

### Gate and metric semantics

- **Counting unit is the sample.** A should-fire sample whose expected rule_id is detected counts as TP, else FN. A should-not-fire sample whose expected rule_id fires counts as FP, else TN. Fires of other rule_ids are recorded as `unexpected_fires` but not gated, so corpus samples need not be orthogonal to every other rule.
- **The harness test never fails on FN/FP counts** (only on corpus coverage gaps and latency). Known false negatives are banked in the corpus first; the fix and the recall improvement land in later PRs with the delta visible in numbers.
- **CI gates FP only, as a rate, in integer arithmetic.** The precision job compares base vs head per rule: fail when `head.fp * base.clean_count > base.fp * head.clean_count`. Cross-multiplication avoids float rounding entirely and normalizes for corpus growth. Recall is intentionally not gated (the asymmetry above); precision is derivable and reported but not separately gated, because with FP rate held, precision can only drop via recall-side changes that the asymmetry deliberately allows. Adding a clean sample that exposes a new FP therefore fails the gate, which is the intended workflow: an FP-exposing sample must ship with the rule fix in the same PR.
- **Bootstrap and rule churn skip.** When base metrics are absent (first PR), empty, or lack a rule_id (new rule), the comparison for that scope is skipped.
- **Latency semantics: NFR-001 measures the check pipeline** (parse + rule dispatch via `collect_violations` with all 39 first-party rules on, oxlint off), excluding process spawn and config resolution. The measurement boundary matches the existing `assert_under_10ms`, but the statistic is stricter: `assert_under_10ms` asserts the mean of its iterations, while the harness asserts the median of ≥50 iterations per sample, which tolerates CI runner spikes. A per-rule_id breakdown is impossible for the 13 `ast_security` rule_ids (constraint 3), so per-toggle latency is recorded as diagnostics without an assertion.

### Scope

- The corpus covers exactly the 39 first-party rule_ids. oxlint-delegated rules are excluded: upstream precision is upstream's responsibility, and the harness must not depend on an oxlint binary.
- `tests/rule_smoke.rs` stays as the spawn-path wiring check. Unifying its fixtures with the corpus (`include_str!` from both sides) is a follow-up; until then the corpus coverage gate (every rule_id needs fire + clean samples) is the drift backstop.
- The CI precision job runs plain `cargo test` rather than nextest: the metrics test is a single named test whose env-driven JSON output path must behave identically on base and head checkouts, and the test job's nextest profile adds nothing there.
- `.github/workflows/ci.yml` adds `src/hook/precision` to the coverage job's `--ignore-filename-regex`, the established treatment for `#[cfg(test)]` modules not named `tests.rs` (doc_catalog precedent), so the C0 delta gate is unaffected.

## Reversibility

The harness is `#[cfg(test)]`-only data and one CI job. Moving fixtures, changing the gate formula, or deleting the whole module touches no production code path. The fp-rate-only gate can be extended with a tp-floor (recall regression detection) later without reshaping the metrics JSON.

## Amendment 2026-06-17: pin the metrics JSON schema as a base-vs-head contract

The Decision Outcome leaves the on-disk metrics JSON shape implicit. This amendment pins it as the cross-process base-vs-head compatibility contract the CI precision delta gate depends on. The decision is unchanged; the schema is made explicit.

`RuleMetrics` serializes as one JSON object per rule_id under `rules`, carrying exactly these fields.

| JSON key            | Rust field (`RuleMetrics`)          | Type |
| ------------------- | ----------------------------------- | ---- |
| `tp`                | `tp`                                | u32  |
| `fn`                | `fn_count` (`serde(rename = "fn")`) | u32  |
| `fp`                | `fp`                                | u32  |
| `tn`                | `tn`                                | u32  |
| `precision`         | `precision`                         | f64  |
| `recall`            | `recall`                            | f64  |
| `latency_us_median` | `latency_us_median`                 | u64  |
| `unexpected_fires`  | `unexpected_fires`                  | u32  |

`MetricsReport` is `{ "rules": { <rule_id>: RuleMetrics }, "toggle_latency_us": { <toggle>: u64 } }`, written by `write_metrics_json` when `GUARDRAILS_METRICS_OUT` is set (`emit_metrics`). `GUARDRAILS_METRICS_OUT` is itself the seam name the workflow YAML and the gate script must agree on.

The gate parses base.json and head.json with jq and compares `fp` against the clean-sample count per rule. The comparison is meaningful only if both checkouts emit the same keys, so the field names and the `serde(rename = "fn")` are a compatibility contract: renaming a field (e.g. `fp` to `false_pos`) makes jq read null on one side, the cross-multiplication then passes vacuously, and the FP/recall gate silently disables with no failing line. A field rename is therefore a breaking change that must update the gate's jq paths in the same PR.

Enforcement, closed by the 2026-06-17 follow-up: the gate's jq filter now resolves each compared field through `// error(...)` and the `.rules` key through the same guard, so a renamed or missing field aborts jq instead of reading null. The `Precision delta gate` step runs that jq under `if ! report=$(...)`, which propagates jq's non-zero exit (a bare assignment had masked it under `set -e`) and fails the job with a schema-drift error. A field rename now blocks the PR with a loud failure rather than silently disabling the FP gate.
