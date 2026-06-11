use super::{Rule, Severity, Violation, RE_ALL_FILES};
use std::sync::LazyLock;

const MARKERS: &[&str] = &[
    "to=functions.",
    "<|channel|>",
    "<|start|>assistant",
    "<thinking>",
];

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_ALL_FILES.clone(),
    checker: Box::new(|content: &str, file_path: &str, _lines: &[(u32, &str)]| {
        // Self-exclusion: this file legitimately contains every marker as literal
        // for detection and tests. Without skipping, any future edit to this rule
        // would be blocked by itself. `replace('\\', "/")` normalizes Windows
        // backslash separators so the suffix match works cross-platform.
        if file_path
            .replace('\\', "/")
            .ends_with("src/rules/cot_leakage_marker.rs")
        {
            return Vec::new();
        }
        let mut violations = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            for marker in MARKERS {
                if line.contains(marker) {
                    violations.push(Violation {
                        rule: super::rule_id::COT_LEAKAGE_MARKER.to_owned(),
                        severity: Severity::High,
                        fix: format!(
                            "AI CoT leakage marker '{marker}' detected. Remove before writing."
                        ),
                        file: file_path.to_owned(),
                        line: Some(u32::try_from(idx + 1).unwrap_or(u32::MAX)),
                        origin: None,
                    });
                }
            }
        }
        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        if !RULE.file_pattern.is_match(path) {
            return Vec::new();
        }
        super::super::check_rule(&RULE, content, path)
    }

    // T-001: detects GPT harmony function call marker
    #[test]
    fn detects_to_functions_marker() {
        let v = check("to=functions.run", "/src/app.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, "cot-leakage-marker");
    }

    // T-002: detects GPT harmony channel marker
    #[test]
    fn detects_channel_marker() {
        let v = check("<|channel|>analysis", "/src/app.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-003: detects GPT harmony assistant start marker
    #[test]
    fn detects_start_assistant_marker() {
        let v = check("<|start|>assistant", "/src/app.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-004: detects Claude thinking tag marker
    #[test]
    fn detects_thinking_marker() {
        let v = check("<thinking>let me reason</thinking>", "/src/app.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-005: clean content passes
    #[test]
    fn ignores_clean_content() {
        let cases = [
            "const x = 1;",
            "function run() { return 42; }",
            "// normal comment",
            "let html = `<div>safe</div>`;",
        ];
        for content in cases {
            assert!(
                check(content, "/src/app.ts").is_empty(),
                "should pass: {content}"
            );
        }
    }

    // T-006: blocks marker inside line comment (no comment exclusion)
    #[test]
    fn blocks_marker_in_line_comment() {
        let v = check("// <thinking>", "/src/app.ts");
        assert_eq!(v.len(), 1, "marker in comment must still block");
    }

    // T-007: blocks marker inside block comment (no comment exclusion)
    #[test]
    fn blocks_marker_in_block_comment() {
        let v = check("/* to=functions.foo */", "/src/app.ts");
        assert_eq!(v.len(), 1);
    }

    // T-008: applies to all file extensions
    #[test]
    fn detects_in_any_file_type() {
        let cases = [
            ("/src/app.ts", "<|channel|>"),
            ("/src/app.py", "<|channel|>"),
            ("/docs/notes.md", "<|channel|>"),
            ("/scripts/run.sh", "<|channel|>"),
            ("/data.json", "<|channel|>"),
        ];
        for (path, content) in cases {
            assert_eq!(check(content, path).len(), 1, "should detect in: {path}");
        }
    }

    // T-009: detects multiple markers across multiple lines
    #[test]
    fn detects_multiple_markers() {
        let content = "line1\n<thinking>\nline3\n<|channel|>\nline5";
        let v = check(content, "/src/app.ts");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].line, Some(2));
        assert_eq!(v[1].line, Some(4));
    }

    // T-010: detects multiple markers on same line
    #[test]
    fn detects_multiple_markers_same_line() {
        let v = check("<|channel|> and <thinking>", "/src/app.ts");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].line, Some(1));
        assert_eq!(v[1].line, Some(1));
    }

    // T-011: fix message names the specific marker
    #[test]
    fn fix_message_includes_marker_name() {
        let v = check("<thinking>", "/src/app.ts");
        assert!(
            v[0].fix.contains("<thinking>"),
            "fix message should name the marker, got: {}",
            v[0].fix
        );
    }

    // T-012: line number reflects actual marker position
    #[test]
    fn line_number_is_one_indexed() {
        let content = "first\nsecond\n<thinking>";
        let v = check(content, "/src/app.ts");
        assert_eq!(v[0].line, Some(3));
    }

    // T-013: skips the rule's own source file (which contains markers as literals)
    #[test]
    fn skips_own_source_file() {
        let v = check(
            "<thinking>\nto=functions.run\n<|channel|>",
            "/Users/x/repo/src/rules/cot_leakage_marker.rs",
        );
        assert!(
            v.is_empty(),
            "rule's own source file must be skipped to allow editing"
        );
    }

    // T-014: bare filename match alone does not skip (full src/rules/ path required)
    #[test]
    fn does_not_skip_bare_filename_match() {
        let v = check("<thinking>", "/some/other/path/cot_leakage_marker.rs");
        assert_eq!(
            v.len(),
            1,
            "files merely ending in cot_leakage_marker.rs (e.g. unrelated copies, fixtures, or other crates) must still be scanned"
        );
    }

    // T-015: Windows-style backslash separator is normalized for self-exclusion
    #[test]
    fn skips_own_source_with_windows_separator() {
        let v = check(
            "<thinking>\nto=functions.run",
            r"C:\Users\x\repo\src\rules\cot_leakage_marker.rs",
        );
        assert!(
            v.is_empty(),
            "self-exclusion must work for Windows-style paths (backslash separator)"
        );
    }
}
