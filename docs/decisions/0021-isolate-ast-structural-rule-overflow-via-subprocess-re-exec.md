---
status: "accepted"
date: 2026-06-17
decision-makers: thkt
---

# Isolate AST structural-rule overflow in a re-exec subprocess and read signal-death as a block

## Context and Problem Statement

The AST structural rules (the seven toggles in `AstRuleFlags`) need oxc's recursive-descent parser. Deeply nested input (deep JSX, ternary or generic chains) overflows the thread stack and aborts the whole process (SIGABRT, exit 134). For a `PreToolUse` hook a process abort is non-blocking: every check is silently bypassed (fail-open), the opposite of the fail-closed posture in ADR-0004 (#314). The pre-parse byte scan `check_excessive_nesting` catches bracket and prefix-operator nesting deterministically, but JSX and ternary chains carry no bracket signature a byte scan can see, so some overflow inputs must still reach the parser. How does the parse run without an abort silently skipping security checks?

## Decision Drivers

- A hook abort must never silently skip security checks; the overflow must resolve to a block, not fail-open.
- Unit tests must not abort the test runner on overflow inputs.
- No new runtime dependency and no startup cost beyond a conditional child spawn.

## Considered Options

- A. In-process `catch_unwind` around the parse.
- B. Parse on a spawned guard thread with a large stack and detect the abort on join.
- C. Re-exec the same binary as a child subprocess and read its exit code (chosen).

## Decision Outcome

Chosen: **Option C**. `lint_with_ast` dispatches the parse and structural rules to a hidden `__ast-child` subcommand via `spawn_ast_child`. The child re-execs the same binary (`env::current_exe`) with the same stack, so it aborts exactly where an in-process parse would; the parent's `wait_with_output` observes the signal-killed exit and maps it to a blocking Violation through `nesting::overflow_violation`.

A is rejected because a stack overflow is a guard-page hardware fault that aborts the process, not an unwinding panic, so `catch_unwind` cannot recover it. B is rejected because Rust aborts the whole process on stack overflow regardless of which thread overflows, so a guard thread does not contain it. C contains the abort in a disposable process whose death the parent can observe.

### Exit-code wire protocol

The parent (`spawn_ast_child`) reads the child exit code as a 3-way protocol.

| Child exit           | Meaning                                  | Parent action (`AstOutcome`)                                                |
| -------------------- | ---------------------------------------- | --------------------------------------------------------------------------- |
| 0                    | stdout holds the JSON `Vec<Violation>`   | decode → `Violations`                                                       |
| 1                    | parse failed or envelope/encode error    | `ParseFailed`: skip structural rules, edit proceeds with a degradation note |
| signal-death / other | stack overflow or unexpected child death | `Overflow`: emit the blocking Violation                                     |

- The child (`run_child`) overrides main()'s exit-70 panic hook with `panic::set_hook` to `exit(1)`: inside the child a panic is a graceful parse-failure (exit 1), a deliberate local inversion of ADR-0004's exit-70 internal-error contract, valid because the parent reinterprets exit 1 as fail-open-with-note and reserves signal-death for the block.
- Every spawn-time failure (`serde_json::to_vec`, `current_exe`, `spawn`, `wait_with_output`, an undecodable exit-0 payload) fails closed to `Overflow`, never falling back to an in-process parse. A fallback would re-open the #314 fail-open for byte-scan-invisible overflow inputs.
- `AstRuleFlags` is the single source for the enabled-rule set across the early-return, the `AstRequest` envelope, and the in-process call, so the three cannot drift apart.

### The cfg!(test) seam and its hazard

`lint_with_ast` selects `run_ast_inprocess` under `cfg!(test)` and `spawn_ast_child` otherwise, because the test binary's entry point cannot dispatch the `__ast-child` subcommand. Unit tests therefore never exercise the child path; deep-overflow regression inputs live only in CLI integration tests. The durable hazard this records: a future refactor to an in-process recovery scheme would pass every unit test while silently reintroducing the fail-open, because no unit test can observe the child or overflow path.

### Two-tier guard relationship

`check_excessive_nesting` (tier 1, an iterative byte scan that never recurses, so it cannot itself overflow) blocks bracket and prefix-operator nesting before the parse; the subprocess (tier 2) catches the byte-scan-invisible cases. Both emit the same `EXCESSIVE_NESTING` rule via `build_violation`, so the two tiers present one consistent block to the caller.

### Confirmation

- CLI integration tests drive deep-overflow inputs through the real binary and assert a blocking exit; this is the only coverage of the child path because `cfg!(test)` removes it from unit tests.
- `violation_survives_json_round_trip` pins the wire contract: `origin` is None-omitted and decoded with `serde(default)` so a missing field cannot silently drop every structural rule.
- Any move off the subprocess model must keep an integration-level overflow test asserting a block.

## More Information

### Reassessment Triggers

- An in-process way to recover a stack overflow (without a subprocess) that is also unit-testable appears: reconsider Option A/B.
- The `cfg!(test)` seam is removed or the child path becomes unit-testable: revisit the integration-only coverage note.
- The hook input contract or oxc gains a non-aborting depth limit: the parser could reject deep input gracefully and the subprocess could retire.
