---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Use the `oxlint/` rule-name prefix as the violation attribution seam

## Context and Problem Statement

Every violation carries a `rule` string. The reporter (`src/io/reporter.rs:8`) splits that string on an `oxlint/` prefix to label the source as either `oxlint` or `guardrails` in the human-facing output. This prefix is therefore a contract spanning three modules: the `rule_id` catalog (`src/rules.rs`) and oxlint adapter that produce the string, and the reporter that consumes it. Nothing states that the prefix is load-bearing, so a contributor renaming an id or changing the oxlint adapter's naming could silently mislabel every delegated violation's origin.

## Decision Drivers

- A reader must be able to tell a guardrails-native violation from an oxlint-delegated one.
- The attribution must derive from data already on the violation, not a parallel field that can drift.
- The seam must survive id additions on either side.

## Considered Options

- **A. Carry an explicit `source` enum field on `Violation`**: removes the string convention but adds a field every producer must set correctly, with its own drift risk.
- **B. Infer source from the rule registry at format time**: the reporter would need to import the catalog and reverse-map ids, coupling output formatting to the rule set.
- **C. Encode attribution in the `rule` string via an `oxlint/` prefix (chosen)**: a single naming convention, zero extra state.

## Decision Outcome

Chosen: **Option C**. The `oxlint/` prefix on a `rule` string is the attribution seam, and must remain true unless superseded.

- `format_rule_name` (`src/io/reporter.rs:8`) strips an `oxlint/` prefix: a match labels the violation `oxlint` and shows the unprefixed name; no match labels it `guardrails`. First-party `rule_id` values (`src/rules.rs`) are therefore reserved to never start with `oxlint/`, and the oxlint adapter must keep emitting that prefix for delegated rules. Renaming a first-party id into the `oxlint/` namespace, or dropping the prefix from the adapter, silently reattributes violations and must not be done without updating this seam.

### Confirmation

A reviewer confirms compliance by checking that no first-party `rule_id` literal in `src/rules.rs` begins with `oxlint/`, and that the oxlint adapter prefixes its delegated rule names. The reporter's split is exercised by formatting tests over both a prefixed and an unprefixed violation.

## Reversibility

Reversal is medium: replacing the string convention with an explicit field touches the producers in `src/rules.rs` and the oxlint adapter plus the reporter consumer, a coordinated 2-3 file change rather than a one-location edit.

## More Information

Records census ADR-gap finding #4 (`src/io/reporter.rs:8-13`) from `docs/audit/2026-06-30-071839-adr-gaps.md`. Related: ADR-0010 (reporter output design intent), which covers the rendered shape but not this attribution seam.
