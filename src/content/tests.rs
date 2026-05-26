use super::*;
use std::path::PathBuf;

fn make_write_input(file_path: Option<&str>, content: Option<&str>) -> ToolInput {
    ToolInput {
        tool_name: ToolName::Write,
        tool_input: ToolInputData {
            file_path: file_path.map(String::from),
            content: content.map(String::from),
            ..ToolInputData::default()
        },
    }
}

fn make_edit_input(file_path: Option<&str>, new_string: Option<&str>) -> ToolInput {
    ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: file_path.map(String::from),
            new_string: new_string.map(String::from),
            ..ToolInputData::default()
        },
    }
}

fn temp_ts_file(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn write_extracts_content() {
    let input = make_write_input(Some("/src/app.ts"), Some("const x = 1;"));
    let ResolvedTarget {
        file_path: path,
        content,
        ..
    } = get_file_and_content(&input, None).unwrap();
    assert_eq!(path, "/src/app.ts");
    assert_eq!(content, "const x = 1;");
}

#[test]
fn edit_extracts_new_string() {
    let input = make_edit_input(Some("/src/app.ts"), Some("const y = 2;"));
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "const y = 2;");
}

#[test]
fn multi_edit_joins_edits() {
    let input = ToolInput {
        tool_name: ToolName::MultiEdit,
        tool_input: ToolInputData {
            file_path: Some("/src/app.ts".to_owned()),
            edits: Some(vec![
                EditItem {
                    new_string: Some("line1".to_owned()),
                    ..EditItem::default()
                },
                EditItem {
                    new_string: Some("line2".to_owned()),
                    ..EditItem::default()
                },
            ]),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "line1\nline2");
}

#[test]
fn multi_edit_join_preserves_separator_before_empty_string() {
    // Regression: the fold-based join silently dropped the leading
    // separator when the first edit's new_string was empty, shifting
    // line offsets in downstream snippet analysis.
    let input = ToolInput {
        tool_name: ToolName::MultiEdit,
        tool_input: ToolInputData {
            file_path: Some("/nonexistent/path.ts".to_owned()),
            edits: Some(vec![
                EditItem {
                    old_string: Some("foo".to_owned()),
                    new_string: Some(String::new()),
                    ..EditItem::default()
                },
                EditItem {
                    old_string: Some("bar".to_owned()),
                    new_string: Some("kept".to_owned()),
                    ..EditItem::default()
                },
            ]),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "\nkept");
}

#[test]
fn multi_edit_empty_edits_returns_none() {
    let input = ToolInput {
        tool_name: ToolName::MultiEdit,
        tool_input: ToolInputData {
            file_path: Some("/src/app.ts".to_owned()),
            edits: Some(vec![]),
            ..ToolInputData::default()
        },
    };
    assert!(get_file_and_content(&input, None).is_none());
}

#[test]
fn multi_edit_all_none_returns_none() {
    let input = ToolInput {
        tool_name: ToolName::MultiEdit,
        tool_input: ToolInputData {
            file_path: Some("/src/app.ts".to_owned()),
            edits: Some(vec![EditItem::default(), EditItem::default()]),
            ..ToolInputData::default()
        },
    };
    assert!(get_file_and_content(&input, None).is_none());
}

#[test]
fn unsupported_tool_returns_none() {
    let input = ToolInput {
        tool_name: ToolName::Other("Bash".to_owned()),
        tool_input: ToolInputData {
            file_path: Some("/tmp/x".to_owned()),
            content: Some("echo hi".to_owned()),
            ..ToolInputData::default()
        },
    };
    assert!(get_file_and_content(&input, None).is_none());
}

#[test]
fn tool_name_deserializes_unknown_to_other_preserving_name() {
    let parsed: ToolName = serde_json::from_str(r#""Bash""#).unwrap();
    assert!(matches!(parsed, ToolName::Other(s) if s == "Bash"));
}

#[test]
fn invalid_path_or_content_returns_none() {
    for (label, path, content) in [
        ("empty path", Some(""), Some("content")),
        ("empty content", Some("/src/app.ts"), Some("")),
        ("missing path", None, Some("content")),
    ] {
        let input = make_write_input(path, content);
        assert!(
            get_file_and_content(&input, None).is_none(),
            "case: {label}"
        );
    }
}

#[test]
fn apply_edit_replaces_first_occurrence() {
    let got = apply_edit("foo bar foo", "foo", "X", false).unwrap();
    assert_eq!(got, "X bar foo");
}

#[test]
fn apply_edit_replace_all_replaces_every_occurrence() {
    let got = apply_edit("foo bar foo", "foo", "X", true).unwrap();
    assert_eq!(got, "X bar X");
}

#[test]
fn apply_edit_returns_none_when_old_string_not_found() {
    assert!(apply_edit("foo", "bar", "X", false).is_none());
    assert!(apply_edit("foo", "bar", "X", true).is_none());
}

#[test]
fn apply_edit_returns_none_when_old_string_empty() {
    assert!(apply_edit("foo", "", "X", false).is_none());
    assert!(apply_edit("foo", "", "X", true).is_none());
}

// TC-001: self-referential new_string. Rust `str::replace` does NOT
// re-scan already-replaced output, so a `new_string` containing the
// `old_string` does not cascade. Documenting this invariant.
#[test]
fn apply_edit_self_referential_new_string_does_not_cascade() {
    let got = apply_edit("a a", "a", "aa", false).unwrap();
    assert_eq!(got, "aa a", "replacen replaces only first occurrence");
    let got_all = apply_edit("a a", "a", "aa", true).unwrap();
    assert_eq!(got_all, "aa aa", "replace does not re-scan output");
}

// TC-008: empty `new_string` is a valid deletion operation.
#[test]
fn apply_edit_deletion_with_empty_new_string() {
    let got = apply_edit("foo bar", "foo ", "", false).unwrap();
    assert_eq!(
        got, "bar",
        "deletes old_string including trailing whitespace"
    );
    let got_all = apply_edit("a-x-b-x-c", "x", "", true).unwrap();
    assert_eq!(got_all, "a--b--c", "replace_all deletes every occurrence");
}

#[test]
fn edit_reads_full_file_and_applies_substitution() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("file.ts");
    fs::write(
        &path,
        "import { exec } from 'child_process';\nconst x = 1;\n",
    )
    .unwrap();
    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("const x = 1;".to_owned()),
            new_string: Some("const y = 2;".to_owned()),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(
        content,
        "import { exec } from 'child_process';\nconst y = 2;\n"
    );
}

#[test]
fn edit_falls_back_to_snippet_when_file_missing() {
    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some("/nonexistent/path/that/does/not/exist.ts".to_owned()),
            old_string: Some("const x = 1;".to_owned()),
            new_string: Some("eval(userInput);".to_owned()),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "eval(userInput);");
}

#[test]
fn edit_falls_back_to_snippet_when_old_string_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("file.ts");
    fs::write(&path, "const a = 1;\n").unwrap();
    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("not in file".to_owned()),
            new_string: Some("eval(userInput);".to_owned()),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "eval(userInput);");
}

#[test]
fn multi_edit_applies_sequentially_to_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("file.ts");
    fs::write(&path, "let a = 1;\nlet b = 2;\n").unwrap();
    let input = ToolInput {
        tool_name: ToolName::MultiEdit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            edits: Some(vec![
                EditItem {
                    old_string: Some("let a = 1;".to_owned()),
                    new_string: Some("let a = 10;".to_owned()),
                    ..EditItem::default()
                },
                EditItem {
                    old_string: Some("let b = 2;".to_owned()),
                    new_string: Some("let b = 20;".to_owned()),
                    ..EditItem::default()
                },
            ]),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "let a = 10;\nlet b = 20;\n");
}

#[test]
fn multi_edit_falls_back_when_file_missing() {
    let input = ToolInput {
        tool_name: ToolName::MultiEdit,
        tool_input: ToolInputData {
            file_path: Some("/nonexistent/path.ts".to_owned()),
            edits: Some(vec![EditItem {
                new_string: Some("eval(userInput);".to_owned()),
                old_string: Some("none".to_owned()),
                ..EditItem::default()
            }]),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget { content, .. } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "eval(userInput);");
}

#[test]
fn read_file_capped_returns_full_for_valid_js() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&tmp, "ok.ts", "const x = 1;\n");
    match read_file_capped(path.to_str().unwrap(), None, true) {
        ContentResolution::Full(c) => assert_eq!(c, "const x = 1;\n"),
        _ => panic!("expected Full"),
    }
}

#[test]
fn read_file_capped_returns_not_applicable_for_non_js() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&tmp, "readme.md", "hello");
    assert!(matches!(
        read_file_capped(path.to_str().unwrap(), None, false),
        ContentResolution::NotApplicable
    ));
}

#[test]
fn read_file_capped_degrades_on_file_not_found() {
    assert!(matches!(
        read_file_capped("/nonexistent/path/that/does/not/exist.ts", None, true),
        ContentResolution::Degraded(DegradedReason::FileNotFound)
    ));
}

#[test]
fn read_file_capped_degrades_on_non_utf8() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("binary.ts");
    fs::write(&path, [0xff, 0xfe, 0xfd, 0xfc]).unwrap();
    assert!(matches!(
        read_file_capped(path.to_str().unwrap(), None, true),
        ContentResolution::Degraded(DegradedReason::NonUtf8Content)
    ));
}

#[test]
fn content_within_cap_accepts_empty() {
    assert!(content_within_cap("", 100));
}

#[test]
fn content_within_cap_accepts_one_byte_under_cap() {
    assert!(content_within_cap(&"a".repeat(99), 100));
}

#[test]
fn content_within_cap_accepts_at_exact_cap() {
    assert!(content_within_cap(&"a".repeat(100), 100));
}

#[test]
fn content_within_cap_rejects_one_byte_over_cap() {
    assert!(!content_within_cap(&"a".repeat(101), 100));
}

#[test]
fn content_within_cap_accepts_zero_cap_only_for_empty() {
    assert!(content_within_cap("", 0));
    assert!(!content_within_cap("a", 0));
}

#[test]
fn read_file_capped_degrades_on_oversized_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("huge.ts");
    let size = usize::try_from(MAX_INPUT_SIZE + 1).unwrap();
    fs::write(&path, "a".repeat(size)).unwrap();
    assert!(matches!(
        read_file_capped(path.to_str().unwrap(), None, true),
        ContentResolution::Degraded(DegradedReason::OversizedFile)
    ));
}

#[test]
fn read_file_capped_accepts_exactly_max_size() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("limit.ts");
    let size = usize::try_from(MAX_INPUT_SIZE).unwrap();
    fs::write(&path, "a".repeat(size)).unwrap();
    match read_file_capped(path.to_str().unwrap(), None, true) {
        ContentResolution::Full(c) => {
            assert_eq!(u64::try_from(c.len()).unwrap(), MAX_INPUT_SIZE);
        }
        _ => panic!("expected Full at exact MAX_INPUT_SIZE boundary"),
    }
}

#[test]
fn read_file_capped_accepts_file_within_explicit_root() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let path = temp_ts_file(&tmp, "ok.ts", "const x = 1;\n");
    match read_file_capped(path.to_str().unwrap(), Some(&root), true) {
        ContentResolution::Full(c) => assert_eq!(c, "const x = 1;\n"),
        _ => panic!("expected Full when file is within explicit root"),
    }
}

#[test]
fn read_file_capped_degrades_when_file_outside_explicit_root() {
    let root_tmp = tempfile::TempDir::new().unwrap();
    let root = fs::canonicalize(root_tmp.path()).unwrap();
    // file lives in a *different* tempdir, outside `root`
    let other_tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&other_tmp, "evil.ts", "const x = 1;\n");
    assert!(matches!(
        read_file_capped(path.to_str().unwrap(), Some(&root), true),
        ContentResolution::Degraded(DegradedReason::PathOutsideProject)
    ));
}

#[cfg(unix)]
#[test]
fn read_file_capped_degrades_on_symlink_pointing_outside_root() {
    use std::os::unix::fs::symlink;
    let root_tmp = tempfile::TempDir::new().unwrap();
    let root = fs::canonicalize(root_tmp.path()).unwrap();
    // Real file outside the root
    let outside_tmp = tempfile::TempDir::new().unwrap();
    let outside = temp_ts_file(&outside_tmp, "secret.ts", "stolen content");
    // Symlink inside root pointing to the outside file
    let link = root_tmp.path().join("evil.ts");
    symlink(&outside, &link).unwrap();
    assert!(matches!(
        read_file_capped(link.to_str().unwrap(), Some(&root), true),
        ContentResolution::Degraded(DegradedReason::PathOutsideProject)
    ));
}

#[test]
fn resolve_edit_content_degrades_on_old_string_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&tmp, "file.ts", "const a = 1;");
    let result = resolve_edit_content(
        path.to_str().unwrap(),
        Some("missing pattern"),
        "x",
        false,
        None,
        true,
    );
    assert!(matches!(
        result,
        ContentResolution::Degraded(DegradedReason::OldStringNotFound)
    ));
}

#[test]
fn resolve_edit_content_not_applicable_without_old_string() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&tmp, "file.ts", "const a = 1;");
    let result = resolve_edit_content(path.to_str().unwrap(), None, "x", false, None, true);
    assert!(matches!(result, ContentResolution::NotApplicable));
}

#[test]
fn resolve_multi_edit_content_degrades_on_mid_failure() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&tmp, "file.ts", "let a = 1;\n");
    let edits = vec![
        EditItem {
            old_string: Some("let a = 1;".to_owned()),
            new_string: Some("let a = 10;".to_owned()),
            ..EditItem::default()
        },
        EditItem {
            old_string: Some("not in file".to_owned()),
            new_string: Some("eval(x);".to_owned()),
            ..EditItem::default()
        },
    ];
    let result = resolve_multi_edit_content(path.to_str().unwrap(), &edits, None, true);
    match result {
        ContentResolution::Degraded(DegradedReason::MultiEditMidFailure(idx)) => {
            assert_eq!(idx, 1, "second edit (index 1) should be the failure point");
        }
        _ => panic!("expected MultiEditMidFailure(1)"),
    }
}

#[test]
fn get_file_and_content_propagates_degraded_reason() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = temp_ts_file(&tmp, "file.ts", "const a = 1;");
    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("missing pattern".to_owned()),
            new_string: Some("eval(x);".to_owned()),
            ..ToolInputData::default()
        },
    };
    let ResolvedTarget {
        content, degraded, ..
    } = get_file_and_content(&input, None).unwrap();
    assert_eq!(content, "eval(x);");
    assert_eq!(degraded, Some(DegradedReason::OldStringNotFound));
}

#[test]
fn degraded_reason_note_contains_actionable_text() {
    let note = DegradedReason::OversizedFile.note();
    assert!(note.contains("exceeds"));
    assert!(note.contains("snippet"));
    let note = DegradedReason::MultiEditMidFailure(2).note();
    assert!(note.contains("edit 2"));
}
