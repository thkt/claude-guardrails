---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Mask comments but preserve string literals, and accept the no-regex-literal scanner limitation

## Context and Problem Statement

Line-regex rules (crypto-weak, hardcoded-secret, and siblings) and the byte/AST structural rules all consume the same hand-written JS/TS scanner (`src/analysis/scanner.rs`) to decide which source bytes are code, string, or comment. Two policies govern that masking and one accepted limitation underlies it, but each lives only as a "what is true now" comment, with no forward rule a future contributor must preserve. A change to any one silently shifts the false-positive / false-negative balance of every rule that scans masked source, and nothing tool-enforces the contract.

## Decision Drivers

- A masked-source change must not silently flip a rule from firing to silent, or vice versa, across the whole line-regex suite.
- The masking must keep `content.lines()` line numbers stable so violation locations stay correct.
- The scanner must keep UTF-8 validity after masking (rules operate on `&str`).
- The accepted limitations must be discoverable by a contributor before they "fix" the scanner and regress a rule.

## Considered Options

- **A. Document each policy only in its own source comment** (status quo): correct today, but the cross-rule invariant is invisible and each comment states fact without the forward rule.
- **B. Invert the masks so `comment` and `code_visible` are complements**: simpler mental model, but it would blank string literals and defeat content-matching rules (crypto-weak matching `'md5'`).
- **C. Pin the policy in one ADR and keep the source comments as the local pointer (chosen)**: the cross-subsystem invariant becomes a single forward contract; comments stay as the inline reminder.

## Decision Outcome

Chosen: **Option C**. The following three points are the masking policy and the accepted limitation, and they must remain true unless this ADR is superseded.

1. **Comment mask blanks comment bytes only; string literals are preserved.** `comment_masked_source` (`src/rules.rs:176`) replaces every comment byte with an ASCII space but leaves string content intact, because crypto-weak and hardcoded-secret match on string _content_ (`'md5'`). Blanking strings (the `code_visible` mask) would defeat them. Newlines and carriage returns are exempt so `.lines()` keeps original line numbering. Only single-byte ASCII spaces overwrite bytes, so UTF-8 stays valid.
2. **`SourceMasks` carries two non-inverse masks.** `comment[i]` flags comment bytes including opener/closer delimiters; `code_visible[i]` keeps code bytes and spaces out string/comment content, but keeps `${...}` interpolation content as code. The two masks deliberately disagree at opener delimiters (`build_source_masks`, `src/analysis/scanner.rs:243`). A contributor must not assume `code_visible[i] == space  ⇔  comment[i]`.
3. **The scanner has no regex-literal support (accepted FN).** A `/` followed by `/` or `*` is always treated as a comment opener, so `/\d+/g` is misidentified as a comment. Disambiguating regex from division needs context-aware parsing beyond the scanner's scope. This is an accepted false-negative class that propagates into nesting and AST masking; widening it requires a deliberate scanner redesign, not a local patch.

### Confirmation

The masking-preservation invariant is regression-guarded by the rule tests that match on string content through the masked pipeline (crypto-weak's `'md5'` cases). The non-inverse mask behavior is exercised by `build_source_masks` callers in nesting and AST masking. A reviewer confirms compliance by checking that any change to `scanner.rs` masking or `comment_masked_source` keeps those tests green and updates this ADR if the policy itself changes.

## Reversibility

Reversal is low: the masking decision is read by every line-regex rule plus nesting and AST masking, so changing it is a coordinated multi-subsystem change with a corpus-wide precision impact, not a one-location edit. Adding regex-literal support is a scanner redesign with its own follow-up.

## More Information

Consolidates census ADR-gap findings #5 (`scanner.rs:1-8`), #6 (`scanner.rs:243-259`), and #23 (`rules.rs:176-204`) from `docs/audit/2026-06-30-071839-adr-gaps.md`. Related: ADR-0021 (AST structural overflow isolation, which consumes the same masked source).
