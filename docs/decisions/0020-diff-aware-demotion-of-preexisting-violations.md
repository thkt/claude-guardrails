---
status: "accepted"
date: 2026-06-10
decision-makers: thkt
---

# Demote preexisting violations to advisory via lazy two-pass diff-aware classification

## Context and Problem Statement

The hook decides block vs advisory from the post-edit content alone. A file that already contains a blocking violation therefore blocks every subsequent edit, including edits that touch unrelated lines. Agents stall on legacy files they did not break (Issue #256).

The issue assumed the fix required a Claude Code hook-input contract extension (before-content or a diff in `tool_input`) and proposed a partial implementation waiting on it. Exploration falsified that premise: `tool_input` carries only `{file_path, content}` for Write and `{file_path, old_string, new_string, replace_all}` for Edit, but the post-edit resolution path (ADR-0007) already reads the pre-edit file from disk via `read_file_capped` as scratch material for reconstructing Edit/MultiEdit content. Retaining that read, and performing the same capped read for Write, yields the before-edit content with zero external dependencies. At PreToolUse time the file on disk is still pre-edit by definition of the hook point.

Three problems remain once before-content is available.

1. **Violation identity across edits.** Line numbers shift under insertion and deletion, so line-based matching is fragile.
2. **Non-local rules.** Rules that decide a violation from whole-file state (e.g. transaction-boundary: multiple writes without a transaction) or that report only the first match cannot be matched per line; a naive comparison under-counts their occurrences and over-demotes.
3. **Incomplete before-pass.** If the before lint degrades (parse failure, capped read, resolver mismatch), demotion decisions based on it are untrustworthy.

## Decision Drivers

- Fail-safe asymmetry: this is a security hook; demoting a genuinely new violation (bypass) is a worse failure than blocking a preexisting one.
- Startup cost constraint: clean edits (the common case) must not pay any additional IO or lint pass.
- Wire compatibility: existing JSON consumers must see byte-identical output while the feature is off.
- Hook contract: stdin JSON with one file's content stays the interface; no new external inputs.

## Considered Options

- **A. Lazy two-pass + (rule, trimmed line text) multiset + locality allowlist (chosen)**
- **B. Line-range diff mapping**: compute edited line ranges from `old_string`/`new_string` and treat only violations inside them as new.
- **C. Per-rule count comparison**: demote while the after count does not exceed the before count, ignoring line text.
- **D. Wait for a Claude Code contract extension** (the issue's original premise).
- **E. Checked-in baseline file**: persist known violations to a committed baseline (ESLint-suppressions style) and block only violations absent from it.

## Decision Outcome

Chosen: **Option A**, gated behind a `diffAware` project-config toggle that ships default-off.

- B is rejected because MultiEdit and `replace_all` make line-range reconstruction fragile, and a violation that merely moved out of the edited range would be misclassified as new; the diff implementation itself is cost without a precision gain.
- C is rejected for the count-collision false negative: fixing one violation while adding another of the same rule keeps the count equal, and the new violation passes unblocked. That is a direct bypass.
- D is rejected because the premise was false; the before content is already on disk and partially already read. Waiting adds an external dependency where none is needed.
- E is rejected because the baseline file would be agent-writable: any process that can edit code can edit the baseline, which turns suppression into a self-service bypass. It also drifts in both directions (fixed violations linger as suppressions; new legacy needs regeneration). Deriving the before-state from the file on disk at decision time leaves no persistent suppressing artifact to forge.

### Mechanism

- **Lazy second pass.** The before content is linted only when the after pass yields at least one blocking violation. With the toggle off or zero blocking violations, no additional read or lint occurs. The second pass runs first-party rules only: oxlint-delegated violations are never demotable, so skipping the subprocess saves latency and keeps the benign oxlint-absent note out of the completeness contract.
- **Identity is (rule_id, trimmed line text), counted as a multiset.** Trimming makes matching robust to indentation changes and line moves. Demotion per identity is capped at the before-count, so pasting an additional copy of an existing violating line still blocks the surplus.
- **Locality allowlist.** Only rules verified to report every occurrence, to decide each violation from a single line, and to report the line whose text alone reproduces the violation are demotable. First-match-only rules (the `find_match_in_lines` family) and rules that report without a line number are excluded; oxlint-delegated violations are excluded because the external tool's reporting shape is not pinned by this repo. Enrollment requires an all-occurrence pin test that fails if a first-match-only rule is enrolled by mistake, plus a demotion-surface corpus pair (below); an enrolled rule without its pair fails the rule-set assert.
- **Demotion-surface corpus.** Every allowlisted rule ships before/after content pairs covering preserved (demotes), added (the new one blocks), and surplus-copy (count-cap blocks) scenarios, verified end-to-end through the first-party lint and the classifier. A violation absent from the before content that gets demoted in any pair is a hard test failure with zero tolerance, no threshold. This pins the third allowlist clause against the rules' real reporting, not hand-written violation lists.
- **Hook-mediated writes only.** Demotion defends edits that arrive through the hook. An agent that can write outside the hook (shell redirection, direct file IO) can already land arbitrary content without any lint, so planting a violation out-of-band and demoting it in a later edit adds no capability beyond what the out-of-band write itself grants. Stated as an explicit assumption in the spec.
- **Completeness contract (fail-loud).** If the before pass emits any note, the content resolution is degraded, or the before read fails for any reason other than file absence, demotion is cancelled entirely and a note states so. A missing file (new-file Write) means every violation is introduced; nothing demotes.
- **Origin visibility.** With the toggle on, every reported violation carries `origin: "introduced" | "preexisting"`; preexisting marks exactly the demoted violations, so non-allowlisted survivors and count-cap surplus stay introduced. Demoted ones render as preexisting in stderr warnings. With the toggle off, the field is omitted via `skip_serializing_if`, keeping the wire format byte-identical (ADR-0005 envelope shapes updated accordingly).
- **Default-off.** The demotion-surface corpus ships as a regression gate, but a synthetic corpus does not represent real edit traffic; for a security hook, default-on is decided after dogfooding the toggle on this repository and observing demotion behavior (`origin`, cancellation notes) in real edits. The toggle lives as a top-level config field beside `enabled`, not in the per-rule toggle macro, because rule toggles carry documentation drift gates sized for rules.

### Confirmation

Spec scenarios T-274 through T-292 (`.claude/workspace/planning/2026-06-10-diff-aware/spec.md`) pin the contract. Key invariants and their tests:

| Invariant                                                | Test                                                                  |
| -------------------------------------------------------- | --------------------------------------------------------------------- |
| Byte-identical wire format while off (no `origin` field) | `format_json_report_omits_origin_when_absent` (`src/io/reporter.rs`)  |
| `origin` serialization while on                          | `format_json_report_emits_origin_when_present` (`src/io/reporter.rs`) |
| Demotion capped at before-count (pasted surplus blocks)  | T-278 (classifier unit)                                               |
| Non-allowlisted rule never demotes                       | T-279 (transaction-boundary unit)                                     |
| Before-pass parse failure cancels demotion with a note   | T-280 (integration)                                                   |
| Exit advisory when every blocking violation demotes      | T-277 (integration)                                                   |
| All-occurrence enrollment pin per allowlisted rule       | T-287 (unit)                                                          |
| Zero bypass across the demotion-surface corpus           | T-291 (corpus measurement)                                            |
| Allowlist enrollment requires a corpus pair              | T-292 (rule-set assert)                                               |

## Reassessment Triggers

- Dogfooding (this repository with `diffAware` on) accumulates real-edit demotion observations with zero bypass findings: re-evaluate default-on.
- A way to pin oxlint's reporting shape appears: consider enrolling oxlint-delegated rules in the allowlist.
- The Claude Code hook input contract starts carrying before-content or a diff: replace the disk read with the contract input and re-derive the pre-edit-disk assumption.
- Evidence that the file on disk is not pre-edit at PreToolUse time: revise immediately; the mechanism would degrade toward demote-everything, which is a bypass.

## Reversibility

The classifier is a new module wired into the hook at one branch point; the toggle defaults off and the off-path wire format is byte-identical. Removing the feature deletes the module, the toggle, and the `origin` field without affecting any existing consumer.
