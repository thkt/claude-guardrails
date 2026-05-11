use super::{Rule, Severity, Violation, RE_ALL_FILES};

const MARKERS: &[&str] = &[
    "to=functions.",
    "<|channel|>",
    "<|start|>assistant",
    "<thinking>",
];

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_ALL_FILES.clone(),
        checker: Box::new(|content: &str, file_path: &str, _lines: &[(u32, &str)]| {
            let mut violations = Vec::new();
            for (idx, line) in content.lines().enumerate() {
                for marker in MARKERS {
                    if line.contains(marker) {
                        violations.push(Violation {
                            rule: super::rule_id::COT_LEAKAGE_MARKER.to_owned(),
                            severity: Severity::High,
                            fix: format!(
                                "AI CoT leakage marker '{}' detected (likely model output contamination). Remove before writing.",
                                marker
                            ),
                            file: file_path.to_owned(),
                            line: Some(u32::try_from(idx + 1).unwrap_or(u32::MAX)),
                        });
                    }
                }
            }
            violations
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        let r = rule();
        if !r.file_pattern.is_match(path) {
            return Vec::new();
        }
        r.check(content, path, &super::super::non_comment_lines(content))
    }

    // T-001: detects GPT harmony function call marker
    #[test]
    fn detects_to_functions_marker() {
        let v = check("to=functions.run", "/src/app.ts");
        assert_eq!(v.len(), 1, "expected 1 violation, got: {:?}", v);
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
                "should pass: {}",
                content
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
            assert_eq!(check(content, path).len(), 1, "should detect in: {}", path);
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
}
