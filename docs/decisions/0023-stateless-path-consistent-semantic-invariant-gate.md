---
status: "accepted"
date: 2026-06-24
decision-makers: thkt
---

# Keep the semantic invariant gate stateless and path-consistent

## Context and Problem Statement

The semantic invariant gate (`src/invariant.rs`, Issue #359) blocks an edit that silently mutates a value pinned in a central `.invariants.json` (feature-flag bool, i18n string, design token). Two of its load-bearing properties are invariants that no type or test can enforce, and both are stated in the module doc as current behavior, not as rules a future contributor must preserve.

1. **No baseline.** The gate compares the post-edit scalar directly against the declared value, with no git, diff, or time reference. The repository already ships diff-aware machinery (ADR-0020) that reads before-content from disk; a contributor reaching for it to make the gate "smarter" (compare against the previous git value) would invert the model while every existing test stays green.
2. **Key consistency.** The pin lookup key is derived from the same canonicalized path the content read used. If a future path-handling change derives the key from the raw path instead, a symlinked ancestor lets the read succeed against the real file while the pin lookup misses, and the mutation passes unchecked. The two code paths must agree, but nothing binds them.

## Decision Drivers

- Both properties are security invariants of a gate whose failure mode is a silent bypass, not a crash.
- Neither is expressible as a type constraint, and a passing test suite does not witness either invariant being broken.
- The breaker for property 1 is concrete, not hypothetical: ADR-0020's diff-aware reader already exists in the same binary.

## Considered Options

- **A. Record both invariants in one ADR (chosen).** Pin the stateless model and the canonical-key consistency as forward rules.
- **B. Comments only.** Rely on the existing module-doc prose.
- **C. Two separate ADRs**, one per invariant.

## Decision Outcome

Chosen: **Option A**.

- B is rejected because the module doc states what the code does, not what must stay true; the incomplete-contract gap is exactly what an ADR closes. The diff-aware breaker (ADR-0020) makes the statelessness drift a live risk a comment does not flag.
- C is rejected because both invariants belong to the same #359 subsystem and share one reader (a contributor changing the gate touches both); splitting them scatters the contract.

### Stateless conformance

The gate is a pure post-edit conformance check: declared scalar versus resolved scalar, nothing else. The human keeps the pin honest by editing `.invariants.json`; an AI edit that drifts a pinned value is rejected in the same cycle. The gate must NOT acquire a git, diff, or temporal baseline. Drift detection that needs history belongs to a different mechanism, not this one.

### Canonical-key consistency

`canonical_relative_key` derives the key through `path_resolve::resolve_under_root`, which follows every component the way `read_file_capped`'s `fs::canonicalize` does and rejoins the components below the nearest existing ancestor unresolved (a new-file Write whose parent does not exist yet). The override matcher, `configGuard` and `invariantGuard` key off the same function, so the four share one resolution space. Any future path handling that feeds the pin lookup MUST stay symlink-consistent with the read path in `content.rs`. Deriving the key from a path the read did not use reopens the symlink bypass.

This section originally named `canonical_path` as that shared canonicalization. It was not: `canonical_path` canonicalizes the parent alone and leaves the final component as spelled, so an edit whose own path was a symlink missed the pin (#471). `is_declaration_path` still uses `canonical_path`, where leaving the final component unresolved is the intended behavior.

### Consequences

- Good, because the two non-enforceable invariants now have a forward rule a reviewer can cite when a change drifts them.
- Good, because the statelessness rule names ADR-0020 as the specific thing not to wire in, so the trap is visible at the point of temptation.
- Bad, because the symlink-consistency rule is a coupling between `invariant.rs` and `content.rs` that an ADR documents but cannot mechanically hold; a coupling test would be stronger if one becomes feasible.

### Confirmation

`src/invariant/tests.rs` pins the observable behavior: declared-scalar mismatch produces a violation, representation-strict number equality (int 50 is not float 50.0) holds, and the canonical/raw key fallback resolves the new-file case. The statelessness invariant has no positive test (its violation is the absence of baseline logic); it is enforced at review time against this ADR. A reviewer seeing a git or diff read added to `invariant.rs`, or a pin key derived from a non-canonicalized path, rejects the change against this record.

## More Information

### Trade-offs

The stateless model accepts that the gate cannot detect a drift that the same edit also re-pins in `.invariants.json` (the human owns that file's honesty). Guarding the declaration file itself is a separate rule, added by the amendment below; the gate in `check_invariants` stays baseline-free.

### References

Source audit: `docs/audit/2026-06-24-014746-adr-gaps.md` (candidate G1 = findings I1 + I5). Relates to ADR-0020 (diff-aware demotion, the baseline machinery this gate deliberately does not use) and ADR-0007 (post-edit content resolution, the read path the key derivation must stay consistent with).

### Reassessment Triggers

- A requirement appears for history-aware drift detection on pinned values: build it as a separate mechanism, do not fold a baseline into this gate.
- The Claude Code hook input contract or `content.rs` changes how paths are resolved before reading: re-derive the canonical-key consistency and update `canonical_relative_key` in lockstep.
- A coupling test that fails when the key path and the read path diverge becomes feasible: add it and downgrade the symlink rule from review-enforced to test-enforced.

## Amendment 2026-08-15: 宣言ファイル自身の弱体化は同一 edit cycle の比較で止める

issue #451 で、`.invariants.json` から pin を消す編集を誰も止めないことが判明した。`check_invariants` は pin された対象ファイルの scalar しか見ないため、宣言そのものを消す編集は素通りする。AI agent は自分を縛る pin を外して、次の編集で自由に値を変えられる。

採用: `src/rules/invariant_guard.rs` を `check_invariants` から独立した rule として足し、`src/invariant.rs` の `declaration_edit_weakens` が pin の消失と値の変更を判定する。

### baseline 禁止との関係

この rule は本 ADR が禁じる baseline を持たない。比較する 2 つの状態は同じ edit cycle の中に閉じている。

| 比較対象          | 出どころ                                    | history 参照 |
| ----------------- | ------------------------------------------- | ------------ |
| 編集前の pin 集合 | `load_invariant_table` による disk 読み取り | 無し         |
| 編集後の pin 集合 | hook 入力から再構成した post-edit 全文      | 無し         |

git、diff、時刻はどれも読まない。禁止しているのは history から導いた baseline であり、同じ hook 実行の中で disk を 1 回読むことは対象外。`check_invariants` 自体は変更しておらず、post-edit scalar と宣言値の直接比較のままになる。

### JSON object でない post-edit 内容

pin を持てない形 (配列、`null`、parse 不能) は、宣言の消失と同じ扱いで弱体化と判定する。次の実行が `Corrupt` として読み、pin の照合が止まるため。編集前に pin が 1 件も無ければ、どの形でも弱体化にはならない。

### post-edit 全文が届かない編集

`.invariants.json` 自体の編集で post-edit 全文を再構成できないとき (oversize、非 UTF-8、IO エラー)、弱体化を判定する材料が無い。この rule は violation を出さず、代わりに note を 1 件出す。判定を飛ばしたことが人に見える形にするため。`check_invariants` が pin 済みファイルに対して出す note と同じ器に載る。

### Related

- `src/invariant.rs` (`declaration_edit_weakens`, `has_any_pin`, `is_declaration_path`, `declaration_body`)
- `src/rules/invariant_guard.rs` (path 一致、Critical の violation、再構成できないときの note)
- `src/invariant/tests.rs` T-578〜T-581, T-588〜T-590, T-593, T-594
- `src/rules/invariant_guard/tests.rs` T-582〜T-584, T-591, T-592, T-595, T-596
- `tests/cli/config.rs` T-585〜T-587, T-597
- issue #451
