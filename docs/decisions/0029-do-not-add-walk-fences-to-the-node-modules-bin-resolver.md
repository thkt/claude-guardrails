---
status: "accepted"
date: 2026-06-30
decision-makers: thkt
---

# Keep the canonicalize-plus-project-root boundary and add no walk fences to the bin resolver

## Context and Problem Statement

`try_resolve_bin` (`src/resolve.rs:183`) finds a `node_modules/.bin/<name>` by walking ancestors of the edited file, then rejects any bin that canonicalizes outside the project root with `OutsideProjectRoot`. It deliberately omits the bounded-depth, `.git`-fence, `$HOME`-fence, and exec-bit checks that its sibling resolvers (formatter, gates) carry. Those siblings are independent copies sharing one guard skeleton, so a contributor "unifying" them by adding the fences here looks like obviously good hardening — but it would regress this resolver's security signal. The reason is recorded as a comment, with no forward rule that it must stay this way.

## Decision Drivers

- A bin resolved outside the project root must surface as a distinct, forensic `OutsideProjectRoot` signal, not a silent miss.
- The boundary must hold for a file Write is creating (the file may not exist yet).
- A globally installed tool must not be silently trusted.

## Considered Options

- **A. Unify with the sibling resolvers' guard skeleton** (depth + `.git` + `$HOME` fences + exec-bit): consistent across resolvers, but a `.git` or `$HOME` fence stops the ancestor walk before an outside bin is reached, converting `OutsideProjectRoot` into a silent `NotFound` and erasing the forensic signal.
- **B. Keep the canonicalize + project-root boundary alone (chosen)**: a stronger implementation of the same containment goal, no fences.

## Decision Outcome

Chosen: **Option B**. The bin resolver's boundary is the following, and the fences must not be added unless this ADR is superseded.

- The walk canonicalizes the resolved bin (not `file_path`, because Write targets a not-yet-existing file) and requires it to start with `project_root`, else rejects with `OutsideProjectRoot`. First-match-wins: a rejected closest bin returns the error without continuing the walk, leaving fallback to the caller. There is no PATH fallback, because a global `oxlint` could sit outside any project root. `project_root: None` disables the boundary and is reserved for tests over tempdirs.
- The bounded-depth, `.git`-fence, `$HOME`-fence, and exec-bit checks from the sibling resolvers are intentionally NOT adopted here: each fence would short-circuit the walk before the canonicalize boundary runs, turning a deliberate `OutsideProjectRoot` rejection into a silent `NotFound`. Keep this boundary, do not add fences.

### Confirmation

A reviewer confirms compliance by checking that `try_resolve_bin` keeps the `canonicalize` + `starts_with(project_root)` boundary and adds no ancestor-walk fence. Resolver tests exercise an in-root bin (resolved), an outside-root bin (`OutsideProjectRoot`), and a missing bin (`NotFound`); a fence would flip the outside-root case to `NotFound` and fail the contract.

## Reversibility

Reversal is medium: the resolver is one function, but it governs the trust boundary that three sibling resolvers intentionally diverge from, so changing it requires re-reasoning that cross-resolver relationship, not a local tweak.

## More Information

Records census ADR-gap finding #14 (`src/resolve.rs:162-200`) from `docs/audit/2026-06-30-071839-adr-gaps.md`.
