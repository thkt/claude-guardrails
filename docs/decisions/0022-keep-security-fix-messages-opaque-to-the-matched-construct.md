---
status: "accepted"
date: 2026-06-17
decision-makers: thkt
---

# Keep security and guard fix messages opaque to the matched construct

## Context and Problem Statement

A guardrails fix message is read by an AI agent inside its edit loop, which is the project's outcome: the agent reads the message and fixes the code without human help. A security or guard rule whose fix message names the exact construct it matched on hands that agent the precise lever to mutate the construct and slip past the rule, turning the remediation hint into a bypass recipe. Two rules hit this independently: `check_excessive_nesting` / `overflow_violation` (`EXCESSIVE_NESTING`, #314) and `check_env_var_fallback` (`ENV_VAR_FALLBACK`, #295). How should security and guard fix messages be worded so the message drives a fix, not a circumvention?

## Decision Drivers

- The message must drive a real fix, not reveal how to evade the rule.
- The matched shape and any threshold must not be inferable from the message alone.
- The convention must be shared, so a future security rule does not re-derive it case by case.

## Considered Options

- A. Name the matched construct for maximum actionability.
- B. Generic messages that state the required action and risk only, never the matched construct (chosen).
- C. Decide per rule with no shared convention.

## Decision Outcome

Chosen: **Option B**, as a cross-cutting convention for security and guard rules. The message states the required action and the risk and never names the matched construct.

- `overflow_violation` / `build_violation` says the nesting is too deep and to flatten and retry; it never states the `BRACKET_DEPTH_LIMIT` or `PREFIX_RUN_LIMIT` thresholds an agent would need to tune input to just under the guard.
- `check_env_var_fallback` says to throw when a required env var is missing and never fall back to a hardcoded secret. The detection also skips identifier-bound fallbacks intentionally, so neither the message nor the detection footprint reveals which fallback shape evades the rule.

A is rejected because actionability bought with construct-naming is a direct bypass lever for an adversarial reader. C is rejected because, with no shared contract, a future security rule's "helpful" construct-named message drifts back into a bypass hint with nothing to catch it.

### Scope

Applies to security and guard rules, the ones an agent has an incentive to bypass. It does not mandate opacity for advisory or style rules, where naming the construct aids a genuine fix and there is no adversarial incentive.

### Relationship to ADR-0014

ADR-0014's carve-outs are a one-file static-analysis false-negative trade-off for `ssr-secret-bleed`, a different rule with a different rationale. The 2026-06-17 census confirmed ADR-0014 does not cover this message-opacity policy.

### Confirmation

Human review only. No repo-wide gate forbids a future security message from naming its construct, so a reviewer must check each new or edited security or guard fix message against this ADR. Recording the gate's absence is itself the point: a contributor adding a construct-named message would pass CI today.

## More Information

### Reassessment Triggers

- A mechanical check over rule fix-message literals that flags construct-naming becomes feasible: add it and downgrade the human-review-only clause.
- A rule appears where construct-opacity measurably lowers fix success and carries no adversarial incentive: narrow the convention's scope.
