---
status: "accepted"
date: 2026-06-24
decision-makers: thkt
---

# Scope test-assertion quality grading to expect() chains, redeemed by any real assertion

## Context and Problem Statement

The `test-assertion` rule (`src/rules/test_assertion.rs`, Issue #345) flags test bodies whose assertions do not really assert: tautological (`expect(x).toBe(x)`), mock-only (only `toHaveBeenCalled`), and weak (only `toBeDefined`/`toBeTruthy`). It runs against AI-generated frontend tests, where a false block on a legitimate test is more damaging than a missed weak one.

Two scope decisions define what the rule means by a weak test, and neither is derivable from the per-class matcher logic.

1. **Expect-only grading.** The three quality classes layer only onto `expect()` chains. A body that verifies through `assert.`/`should.`/`.rejects` is trusted as real verification and is graded only for the zero-assertion case, never downgraded for quality. The rule trusts non-expect assertion styles wholesale.
2. **Whole-body redemption.** A single value-verifying assertion anywhere in the body (`classify`'s `verifies_value`) suppresses every quality finding for that body. One strong assertion redeems a body that also contains weak or mock-only ones.

Both are false-positive-suppression choices. If a future change expands the matcher vocabulary or the graded surface, it silently changes which tests fire, with green CI.

## Decision Drivers

- Advisory rule on AI-authored tests: a false block (downgrading a genuinely strong body) costs more than a false negative (missing a weak one).
- The graded surface (`expect()` only) and the redemption rule are non-tool-enforceable invariants: a test pins the current behavior, but nothing forbids quietly widening the surface.
- Matcher vocabulary and the redemption threshold are tuning heuristics that should be free to evolve; over-documenting them risks lock-in.

## Considered Options

- **A. Record the scope contract (expect-only + redemption) as one ADR (chosen).** Pin what the rule deliberately does not grade and why.
- **B. Comments only**, relying on the `classify` doc comment.
- **C. Grade non-expect assertions too**, extending the taxonomy across all assertion styles.

## Decision Outcome

Chosen: **Option A**.

- B is rejected because the `classify` comment states the expect-only layering as fact but no rule forbids extending the matcher vocabulary into non-expect assertions, which would change which tests get flagged. The redemption rule (`verifies_value`) carries no source rationale at all.
- C is rejected as scope creep against the false-positive driver: `assert`/`chai`/`should` matcher families are large and idiomatically varied, and grading them would multiply false blocks on tests the rule has no signal to judge. The expect-only boundary is the deliberate limit, not an oversight.

### Expect-only grading

Quality grading (tautological / mock-only / weak) applies only to `expect()` chains collected by `ExpectCollector`. A body with assertions but no `expect()` chain returns `None` (a non-expect assertion is trusted to verify a value). The graded surface MUST stay `expect()` chains. Widening it to other assertion styles is a scope change that requires re-evaluating the false-positive cost on real AI-authored tests first, not a silent matcher-list edit.

### Whole-body redemption

`verifies_value` is true when the body contains any non-expect assertion OR any `expect()` chain that is not weak, mock, or tautological. When true, `classify` returns `None` and emits nothing. One real assertion redeems the whole body. This favors silence over flagging mixed bodies and is the rule's definition of an unverified test: a test is weak only when every assertion in it is weak. Changing the redemption granularity (e.g. per-assertion flagging) changes what the rule asserts about test quality and is a contract change, not a tuning tweak.

### Consequences

- Good, because the two suppression boundaries that define the rule's meaning now have a forward rule a reviewer cites when a change widens the graded surface.
- Good, because the expect-only limit is recorded as deliberate, so a future contributor does not "complete" the rule by grading `assert`/`should` and reintroduce false blocks.
- Bad, because the redemption rule means a body with one strong and several weak assertions emits nothing; a noisier rule would catch the weak ones, and this ADR locks in the quieter choice until evidence says otherwise.

### Confirmation

`src/rules/test_assertion.rs` tests pin the behavior: `allows_weak_matcher_alongside_strong_assertion`, `allows_mock_matcher_alongside_value_assertion`, and `allows_weak_matcher_alongside_non_expect_assertion` exercise whole-body redemption; the non-expect-assertion path returning `None` pins expect-only grading. A reviewer seeing the graded surface widened beyond `expect()` chains, or `verifies_value` changed to per-assertion granularity, rejects the change against this ADR unless the false-positive cost on real tests is re-measured.

## More Information

### Trade-offs

The matcher vocabulary (`WEAK_MATCHERS` / `MOCK_MATCHERS` / `EQUALITY_MATCHERS`) and severity mapping (weak = Low, others = Medium, mirroring ADR-0018's advisory floor) are statement-of-fact constants, their own source of truth, and stay out of this ADR; only the scope boundaries they operate within are recorded here. The upstream-sync obligation for those lists (tracking new Jest/Vitest matchers) is a maintenance comment in the const block, not an ADR concern.

### References

Source audit: `docs/audit/2026-06-24-014746-adr-gaps.md` (candidate G2 = finding T1, with T2 as the redemption subsection). ADR-0009 (custom-rule overlap eval) was confirmed unrelated: it covers oxlint dedup, not assertion-quality grading. Severity floor follows ADR-0018.

### Reassessment Triggers

- Dogfooding shows the redemption rule hides weak assertions in mixed bodies that matter: re-evaluate per-assertion granularity.
- A reliable signal for grading non-expect assertion styles appears: reconsider widening the graded surface, with a fresh false-positive measurement.
