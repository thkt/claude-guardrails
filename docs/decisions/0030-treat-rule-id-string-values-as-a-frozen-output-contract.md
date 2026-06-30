---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Treat `rule_id` string values as a frozen public output contract

## Context and Problem Statement

The `rule_id` constants in `src/rules.rs:42` define string values (`"crypto-weak"`, `"open-redirect"`, …) that are emitted verbatim in the JSON envelope's `rule` field and referenced in the public README rule tables. They are a consumer-facing identifier: an agent or CI script keying off the `rule` field, and the README, both depend on the exact strings. The module doc documents only HOW to add an id (which allowlist to extend), never that the string _values_ are a compatibility surface. A contributor renaming a value to "improve" it would silently break every downstream consumer with no failing test on the rename itself.

## Decision Drivers

- A consumer keying off the JSON `rule` field must not break when guardrails is upgraded.
- The README rule names must stay stable references.
- Adding a rule must stay easy; only renaming an existing value is the constrained operation.

## Considered Options

- **A. Treat `rule_id` values as internal and freely renamable**: simplest for contributors, but breaks the JSON `rule` field and README references silently on any rename.
- **B. Version the `rule` field separately from the constant names**: adds an indirection layer for a value set that is already stable.
- **C. Freeze the string values as an output contract (chosen)**: the constant names may refactor, but the string literals are consumer-visible and renaming one is a breaking change.

## Decision Outcome

Chosen: **Option C**. The `rule_id` string values are a frozen output contract, and must remain stable unless this ADR is superseded.

- The `define_rule_ids!` macro (`src/rules.rs:42`) defines each id as a `pub const` whose _string value_ flows to `Violation.rule` → the JSON envelope `rule` field (ADR-0005 pins the envelope shape, not which ids are stable) and to the README rule tables. The Rust constant _name_ may be refactored freely; the string _value_ may not. Renaming a value (e.g. `"crypto-weak"` → `"weak-crypto"`) is a breaking change to the JSON output and README references, and must be treated as such (changelog, consumer migration), not done as a cleanup.
- Adding a new id stays unconstrained: extend the catalog and the matching allowlist (`REGISTERED_RULE_IDS` / `UNREGISTERED_RULE_IDS`), gated by `tests::rule_id_catalog_entries_match_allowlists`. That gate enforces presence, not value stability — the stability of existing values is this ADR's job.

### Confirmation

A reviewer confirms compliance by checking that a diff renaming an existing `rule_id` string literal is flagged as a breaking output change (not merged as a refactor). The catalog/allowlist gate (`rule_id_catalog_entries_match_allowlists`) and the README drift gates confirm new ids are wired, but neither blocks a value rename, so the human review is the enforcement point.

## Reversibility

Reversal is low: the values are emitted into the public JSON schema and the published README, so changing one requires a consumer-facing migration (changelog, possibly a deprecation window), not a one-location edit.

## More Information

Records census ADR-gap finding #22 (`src/rules.rs:42-96`) from `docs/audit/2026-06-30-071839-adr-gaps.md`. Related: ADR-0005 (JSON envelope and sysexits), which pins the envelope shape but not the stability of individual `rule` values.
