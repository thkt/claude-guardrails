---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Fail open on a benign parse failure, fail closed on an invisible stack overflow

## Context and Problem Statement

The hook's AST pass (`lint_with_ast`, `src/hook.rs`) can end three ways: structural violations, a benign parse failure, or a stack overflow the byte scan cannot see. The hook must decide, per outcome, whether to block the edit (fail closed) or let it proceed with a note (fail open). The choice is split deliberately — a parse failure fails open, an overflow fails closed — but that policy split lives only in the `AstOutcome` enum doc-comments. ADR-0004 is the generic fail-mode policy and ADR-0021 covers the subprocess isolation mechanism; neither states why these two AST outcomes resolve in opposite directions. A contributor unifying them would silently regress either coverage or safety.

## Decision Drivers

- A parse failure on an unsupported-but-legitimate file must not block the user's edit.
- An input that aborts the parser must never slip through unscanned (the #314 fail-open this closes).
- The most important byte-scan checks must run regardless of parse outcome.
- The policy must be a stated contract, not an inference from enum variants.

## Considered Options

- **A. Fail open on both outcomes**: a stack overflow (deep JSX / ternary / generics) carries no byte-scan signature, so failing open lets genuinely dangerous structure through unscanned — the #314 regression.
- **B. Fail closed on both outcomes**: blocks every edit to a file the parser merely does not support, punishing legitimate work for a coverage gap.
- **C. Split by cause (chosen)**: a benign parse failure fails open; an overflow fails closed.

## Decision Outcome

Chosen: **Option C**. The fail-mode policy for the AST pass is the following, and must remain true unless superseded.

1. **A benign parse failure fails OPEN.** `AstOutcome::ParseFailed` (`src/hook.rs:54`) skips the structural rules and lets the edit proceed with a degraded-coverage note. An unsupported file type or a parser panic is not evidence of a violation, so blocking it would punish legitimate edits (#294).
2. **A byte-scan-invisible overflow fails CLOSED.** `AstOutcome::Overflow` blocks the edit (High violation, exit 2). Deep JSX / ternary / generics abort the parser with no bracket signature the tier-1 byte scan can catch, so the only safe direction is to block (#314).
3. **Cause-independent checks run before the parse.** `check_bidi` (when `ast_security` is on) and `check_excessive_nesting` (unconditional, because the parse runs for any AST rule) execute before the parse, so a parse abort cannot skip the highest-value security checks. Excessive nesting is itself a deliberate block with no note, since the High violation already rejects the edit.

The mechanism that realizes "fail closed on overflow" — re-executing the parse in a child subprocess and mapping its exit code — is ADR-0021's domain. This ADR fixes the policy (which outcome blocks); ADR-0021 fixes the mechanism (how the overflow is contained and signaled).

### Confirmation

The split is regression-guarded by the hook tests that drive a parse-failing input (expects proceed-with-note) and an overflow-inducing input (expects block / exit 2). A reviewer confirms compliance by checking that `ParseFailed` keeps the edit proceeding, `Overflow` blocks, and the pre-parse `check_bidi` / `check_excessive_nesting` ordering is preserved. Collapsing the two outcomes to one direction must update this ADR.

## Reversibility

Reversal is medium: the policy is read at the `match outcome` site and the two enum variants within `src/hook.rs`, but flipping either direction changes the security/usability contract the corpus and #294/#314 regression tests pin, so it is a deliberate policy change, not an incidental edit.

## More Information

Records census ADR-gap finding #18 (`hook.rs:54`) from `docs/audit/2026-06-30-071839-adr-gaps.md`. Related findings route to existing ADRs: pre-parse ordering (#17) to ADR-0004, the child re-exec exit-code wire contract (#19) and spawn-failure-blocks (#20) to ADR-0021, and the unresolved-project-root asymmetry (#21) to ADR-0007.
