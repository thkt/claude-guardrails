//! Pre-parse depth guard (#314), tier 1. oxc's recursive-descent parser
//! overflows the thread stack on deeply nested input and aborts (SIGABRT, exit
//! 134), which is non-blocking for a `PreToolUse` hook — every check is silently
//! bypassed (fail-open). `check_excessive_nesting` runs an iterative byte scan
//! BEFORE the parse and blocks bracket nesting (`()[]{}`) and prefix-operator
//! runs (`!`/`~`) once they cross a threshold far above any real-world code
//! (corpus bracket-depth max 27, `!`-run 3). It is deterministic and
//! false-positive-free, but it can only see depth a byte carries: deep JSX and
//! ternary chains overflow with no bracket signature. Those are caught by tier 2
//! (the parse runs in a child subprocess; see `analysis::ast_rules`), and when
//! that child aborts the hook calls `overflow_violation` to emit the same
//! blocking Violation. See `.claude/workspace/planning/2026-06-16-deep-nest-guard/`.

use crate::analysis::scanner;
use crate::rules::{rule_id, Severity, Violation};

/// Net `()[]{}` nesting depth that triggers a block. Measured 1 MiB debug
/// overflow floor ~282; corpus real-world max 27. 100 keeps ~2.8x margin below
/// the floor and 3.7x above real code.
const BRACKET_DEPTH_LIMIT: i32 = 100;

/// Consecutive `!`/`~` prefix-operator run that triggers a block. Measured
/// 1 MiB debug overflow floor ~900; corpus real-world max 3.
const PREFIX_RUN_LIMIT: u32 = 50;

/// Iterative O(n) byte scan over `code_visible` (strings/comments masked to
/// ASCII space, template interpolation kept) so brackets inside string/comment
/// text do not inflate the count. Never recurses, so it cannot itself overflow
/// at any input depth. Returns the first threshold breach, or None.
pub fn check_excessive_nesting(content: &str, file_path: &str) -> Option<Violation> {
    let masks = scanner::build_source_masks(content);
    let code = &masks.code_visible;

    let mut depth: i32 = 0;
    let mut prefix_run: u32 = 0;

    for (i, &b) in code.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => {
                depth += 1;
                if depth >= BRACKET_DEPTH_LIMIT {
                    return Some(violation(content, file_path, i));
                }
                prefix_run = 0;
            }
            b')' | b']' | b'}' => {
                // Clamp at 0: unbalanced closers must not drive the counter
                // negative and mask a later genuine opener run.
                depth = depth.saturating_sub(1).max(0);
                prefix_run = 0;
            }
            b'!' | b'~' => {
                prefix_run += 1;
                if prefix_run >= PREFIX_RUN_LIMIT {
                    return Some(violation(content, file_path, i));
                }
            }
            // Whitespace holds a prefix run across `!\n!` without resetting; any
            // other byte ends the run.
            b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => prefix_run = 0,
        }
    }
    None
}

fn violation(content: &str, file_path: &str, byte: usize) -> Violation {
    // Lazily build line offsets only on a hit (rare), matching `check_bidi`.
    let line_offsets = scanner::build_line_offsets(content);
    let line = u32::try_from(scanner::offset_to_line(&line_offsets, byte))
        .expect("line count exceeds u32::MAX despite input size cap");
    build_violation(file_path, Some(line))
}

/// Tier-2 overflow block (#314): the child subprocess aborted while parsing, so
/// the byte scan missed the depth (deep JSX / ternary / generics). No specific
/// offset is known, so `line` is None. Same rule and message as the byte-scan
/// hit so the two tiers present one consistent block to the caller.
pub fn overflow_violation(file_path: &str) -> Violation {
    build_violation(file_path, None)
}

fn build_violation(file_path: &str, line: Option<u32>) -> Violation {
    Violation {
        rule: rule_id::EXCESSIVE_NESTING.to_owned(),
        severity: Severity::High,
        // Scope-free: naming the matched construct would hand an AI agent the
        // exact lever to tweak and slip past the guard. State the action only.
        fix: "Nesting is too deep and would crash the checker before any rule \
              runs; flatten the structure and retry."
            .to_owned(),
        file: file_path.to_owned(),
        line,
        origin: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parens(n: usize) -> String {
        format!("const x = {}1{};", "(".repeat(n), ")".repeat(n))
    }

    // T-314-1: deep nested parens block.
    #[test]
    fn blocks_deep_nested_parens() {
        let v = check_excessive_nesting(&parens(150), "/x.ts").expect("should block");
        assert_eq!(v.rule, rule_id::EXCESSIVE_NESTING);
        assert_eq!(v.severity, Severity::High);
    }

    // T-314-2: mixed bracket kinds count toward one net depth.
    #[test]
    fn blocks_deep_mixed_brackets() {
        let open = "([{".repeat(50); // 150 openers
        let close = "}])".repeat(50);
        let src = format!("const x = {open}1{close};");
        assert!(check_excessive_nesting(&src, "/x.ts").is_some());
    }

    // T-314-3: bracket boundary — 99 passes, 100 blocks.
    #[test]
    fn bracket_boundary() {
        assert!(check_excessive_nesting(&parens(99), "/x.ts").is_none());
        assert!(check_excessive_nesting(&parens(100), "/x.ts").is_some());
    }

    // T-314-4: long `!` prefix run blocks.
    #[test]
    fn blocks_prefix_run() {
        let src = format!("const x = {}1;", "!".repeat(100));
        let v = check_excessive_nesting(&src, "/x.ts").expect("should block");
        assert_eq!(v.rule, rule_id::EXCESSIVE_NESTING);
    }

    // T-314-5: prefix boundary — 49 passes, 50 blocks.
    #[test]
    fn prefix_boundary() {
        let pass = format!("const x = {}1;", "!".repeat(49));
        let block = format!("const x = {}1;", "!".repeat(50));
        assert!(check_excessive_nesting(&pass, "/x.ts").is_none());
        assert!(check_excessive_nesting(&block, "/x.ts").is_some());
    }

    // T-314-6: brackets inside a string literal are masked out.
    #[test]
    fn ignores_brackets_in_string() {
        let inner = "(".repeat(120);
        let src = format!("const s = \"{inner}\";");
        assert!(check_excessive_nesting(&src, "/x.ts").is_none());
    }

    // T-314-7: legit depth just above corpus max (27) passes.
    #[test]
    fn allows_realistic_depth() {
        assert!(check_excessive_nesting(&parens(30), "/x.ts").is_none());
    }

    // T-314-8: angle-bracket generics are not counted (low real bracket depth).
    #[test]
    fn ignores_angle_generics() {
        let mut t = String::from("type T = ");
        for _ in 0..30 {
            t.push_str("Array<");
        }
        t.push_str("number");
        for _ in 0..30 {
            t.push('>');
        }
        t.push(';');
        assert!(check_excessive_nesting(&t, "/x.ts").is_none());
    }

    // T-314-10: `-` prefix run is iterative-safe and not counted.
    #[test]
    fn allows_minus_run() {
        let src = format!("const x = {}1;", "-".repeat(100));
        assert!(check_excessive_nesting(&src, "/x.ts").is_none());
    }
}
