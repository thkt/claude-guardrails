---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Fail open on a benign parse failure, fail closed on an invisible stack overflow

## Context and Problem Statement

The hook's AST pass (`lint_with_ast`, `src/hook.rs`) can end with structural violations, a benign parse failure, an internal checker failure, or a stack overflow the byte scan cannot see. The hook must decide, per outcome, whether to block the edit (fail closed) or let it proceed with a note (fail open). Only a parser-reported failure fails open; an incomplete checker run or process abort fails closed. ADR-0004 is the generic fail-mode policy and ADR-0021 covers the subprocess isolation mechanism, so this ADR records the AST-specific split.

## Decision Drivers

- A parse failure on an unsupported-but-legitimate file must not block the user's edit.
- A real Rust panic or invalid success payload means the checker did not complete and must block.
- An input that aborts the parser must never slip through unscanned (the #314 fail-open this closes).
- The most important byte-scan checks must run regardless of parse outcome.
- The policy must be a stated contract, not an inference from enum variants.

## Considered Options

- **A. Fail open on both outcomes**: a stack overflow (deep JSX / ternary / generics) carries no byte-scan signature, so failing open lets genuinely dangerous structure through unscanned — the #314 regression.
- **B. Fail closed on both outcomes**: blocks every edit to a file the parser merely does not support, punishing legitimate work for a coverage gap.
- **C. Split by cause (chosen)**: a benign parse failure fails open; an overflow fails closed.

## Decision Outcome

Chosen: **Option C**. The fail-mode policy for the AST pass is the following, and must remain true unless superseded.

1. **A benign parse failure fails OPEN.** An unsupported source type or oxc's parser-reported `ret.panicked` makes `with_parsed_program` return `None`; `run_child` returns 1, and `AstOutcome::ParseFailed` skips the structural rules while the edit proceeds with a degraded-coverage note (#294).
2. **An internal checker failure fails CLOSED.** A real Rust panic in the AST child inherits main's `Internal` (exit 70) panic hook. The parent maps that and any other numbered non-1 failure to `AstOutcome::InternalFailure`; an exit-0 payload that cannot decode takes the same path. The dedicated checker-failure Violation blocks because the structural pass did not complete.
3. **A byte-scan-invisible overflow fails CLOSED.** Signal death maps to `AstOutcome::Overflow` and blocks the edit (High violation, exit 2). Deep JSX / ternary / generics abort the parser with no bracket signature the tier-1 byte scan can catch, so the only safe direction is to block (#314). Request serialization, child spawn, and wait failures remain on this fail-closed `Overflow` path.
4. **Cause-independent checks run before the parse.** `check_bidi` (when `ast_security` is on) and `check_excessive_nesting` (unconditional, because the parse runs for any AST rule) execute before the parse, so a parse abort cannot skip the highest-value security checks. Excessive nesting is itself a deliberate block with no note, since the High violation already rejects the edit.

The mechanism that realizes these outcomes — re-executing the parse in a child subprocess and classifying its status and output — is ADR-0021's domain. This ADR fixes the policy (which outcomes block); ADR-0021 fixes the mechanism (how they are contained and signaled).

### Confirmation

The split is regression-guarded by tests for `ParseFailed`, exit-70 classification and its dedicated blocking Violation, and overflow (expects block / exit 2). A reviewer confirms that `ParseFailed` keeps the edit proceeding, `InternalFailure` and `Overflow` block, and the pre-parse `check_bidi` / `check_excessive_nesting` ordering is preserved. Changing any direction must update this ADR.

## Reversibility

Reversal is medium: the policy is read at the `match outcome` site and the two enum variants within `src/hook.rs`, but flipping either direction changes the security/usability contract the corpus and #294/#314 regression tests pin, so it is a deliberate policy change, not an incidental edit.

## More Information

Records census ADR-gap finding #18 (`hook.rs:54`) from `docs/audit/2026-06-30-071839-adr-gaps.md`. Related findings route to existing ADRs: pre-parse ordering (#17) to ADR-0004, the child re-exec exit-code wire contract (#19) and spawn-failure-blocks (#20) to ADR-0021, and the unresolved-project-root asymmetry (#21) to ADR-0007.
