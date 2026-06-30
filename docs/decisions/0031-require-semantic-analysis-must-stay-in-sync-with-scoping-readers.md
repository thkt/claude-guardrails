---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# A rule that reads scoping must extend `requires_semantic` and tolerate absent scoping

## Context and Problem Statement

`check_program` (`src/analysis/ast_security.rs:139`) builds oxc's `SemanticBuilder` (scope / symbol / reference resolution) lazily — only when `postmessage::requires_semantic(program)` returns true — because that resolution is the heaviest post-parse step and currently feeds only the postMessage origin check. The "skipping it is behavior-neutral elsewhere" claim rests on a statement of current fact: no other rule reads the `symbol_id` / `reference_id` data the build populates. It carries no forward rule. A future rule that reads `scoping` but forgets to extend `requires_semantic` would get `scoping == None` on most files and silently under-report, with no compile error and no obvious failing test.

## Decision Drivers

- Handler-less files (the majority) must skip the expensive semantic build (the #293 latency win).
- A new scoping-reading rule must not silently lose coverage because the build was skipped.
- The coupling between "who reads scoping" and "when the build runs" must be a stated contract, since the type system does not enforce it.

## Considered Options

- **A. Always build the semantic model**: removes the footgun, but pays the heaviest post-parse cost on every file including the handler-less majority, regressing #293.
- **B. Keep the lazy build, document only the current fact** (status quo): correct today, but a future scoping reader silently breaks.
- **C. Keep the lazy build and pin the forward rule as an ADR (chosen)**: the latency win stays; the contract for future readers is explicit.

## Decision Outcome

Chosen: **Option C**. The lazy-semantic contract is the following, and must remain true unless superseded.

- `check_program` builds the semantic model only when `postmessage::requires_semantic(program)` is true, and passes `scoping` (`Option`) into the visitor. This is a deliberate latency optimization for handler-less files (#293).
- Any new or changed rule that reads `scoping` (symbol/reference resolution) MUST do both: (1) extend `requires_semantic` so the build is triggered for the inputs that rule cares about, and (2) tolerate `scoping == None` without panicking, since the build is still skipped for unrelated files. Reading `scoping` without extending `requires_semantic` produces a silent false negative, not an error.

### Confirmation

A reviewer confirms compliance by checking that every `scoping`-reading site has a corresponding condition in `requires_semantic`, and that each handles the `None` case. The postMessage origin tests exercise the built path; a new scoping reader must add a test whose input would be skipped by the current `requires_semantic`, proving the predicate was extended.

## Reversibility

Reversal is medium: changing the policy means touching `check_program`, `requires_semantic`, and every scoping reader together, since they are the two halves of one invariant.

## More Information

Records census ADR-gap finding #25 (`src/analysis/ast_security.rs:133-141`) from `docs/audit/2026-06-30-071839-adr-gaps.md`.
