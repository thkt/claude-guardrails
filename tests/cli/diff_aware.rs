// Diff-aware demotion through the real binary: blocking violations that
// already existed in the before-edit file demote to advisory; violations the
// edit introduces keep blocking. Tests opt in via diffAware:true (except the
// toggle-off wire-format pin) and pin oxlint off so first-party rules are the
// only violation source.

use crate::common::{run_guardrails_with, tmp_repo_with_claude};
use std::fs;
use std::path::Path;
use std::process::Output;

fn enable_diff_aware(dir: &Path) {
    fs::write(
        dir.join(".claude/tools.json"),
        r#"{"guardrails": {"diffAware": true, "rules": {"oxlint": false}}}"#,
    )
    .unwrap();
}

fn run_json(json: &str, dir: &Path) -> Output {
    run_guardrails_with(
        json.as_bytes(),
        Some(dir),
        &[("NO_COLOR", "1")],
        &["--json"],
    )
}

fn edit_json(file: &Path, old_string: &str, new_string: &str) -> String {
    serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": file.to_string_lossy(),
            "old_string": old_string,
            "new_string": new_string
        }
    })
    .to_string()
}

fn write_json(file: &Path, content: &str) -> String {
    serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": file.to_string_lossy(),
            "content": content
        }
    })
    .to_string()
}

// T-274: with the toggle off the wire format is unchanged: no origin key
// appears in the JSON envelope even though violations are reported.
#[test]
fn toggle_off_omits_origin_from_json() {
    let tmp = tmp_repo_with_claude();
    fs::write(
        tmp.path().join(".claude/tools.json"),
        r#"{"guardrails": {"rules": {"oxlint": false}}}"#,
    )
    .unwrap();
    let file = tmp.path().join("app.ts");
    fs::write(&file, "eval(old);\n").unwrap();

    let json = edit_json(&file, "eval(old);", "eval(old);\neval(brandNew);");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "toggle off keeps every violation blocking; stdout: {stdout}"
    );
    assert!(
        !stdout.contains(r#""origin""#),
        "toggle-off JSON must not contain an origin key: {stdout}"
    );
}

// T-276: an edit that keeps an existing eval line and adds a new one blocks
// only the new violation; the pre-existing one surfaces as a warning.
#[test]
fn edit_adding_new_violation_blocks_it_and_demotes_preexisting_one() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "eval(old);\n").unwrap();

    let json = edit_json(&file, "eval(old);", "eval(old);\neval(brandNew);");
    let output = run_json(&json, tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "newly added eval must block; stderr: {stderr}"
    );
    assert!(
        stderr.contains("Fix 1 issue "),
        "exactly one blocking violation expected: {stderr}"
    );
    assert!(
        stderr.contains("1 warning"),
        "pre-existing eval must demote to a warning: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""origin":"introduced""#),
        "the new eval must carry origin introduced: {stdout}"
    );
    assert!(
        stdout.contains(r#""origin":"preexisting""#),
        "the demoted eval must carry origin preexisting: {stdout}"
    );
    assert!(
        stderr.contains("preexisting"),
        "human warning output must mark the demoted violation: {stderr}"
    );
}

// T-277: an edit touching only a harmless line demotes the untouched
// pre-existing violation, so the hook exits advisory and lets the edit pass.
#[test]
fn edit_keeping_preexisting_violation_exits_advisory() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "eval(old);\nconst a = 1;\n").unwrap();

    let json = edit_json(&file, "const a = 1;", "const a = 2;");
    let output = run_json(&json, tmp.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "all blocking violations pre-exist, so exit must be advisory; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("BLOCKED"),
        "no blocking section expected: {stderr}"
    );
    assert!(
        stderr.contains("1 warning"),
        "pre-existing eval must surface as a warning: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""origin":"preexisting""#),
        "the demoted eval must carry origin preexisting: {stdout}"
    );
}

// T-280: when the before-edit content does not parse, the before pass is
// incomplete, so demotion is skipped entirely and a note says why.
#[test]
fn unparsable_before_content_skips_demotion_with_note() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "broken((\neval(x);\n").unwrap();

    let json = edit_json(&file, "broken((", "fixed();");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "demotion must be skipped, keeping eval blocking; stdout: {stdout}"
    );
    assert!(
        stdout.contains("demotion skipped"),
        "envelope notes must state demotion was skipped: {stdout}"
    );
}

// T-281: writing to a path with no existing file is the legitimate new-file
// case: every violation blocks and no demotion-skip note appears.
#[test]
fn write_to_new_file_blocks_all_without_skip_note() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("brand_new.ts");

    let json = write_json(&file, "eval(x);\n");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "violations in a new file are all introduced; stdout: {stdout}"
    );
    assert!(
        !stdout.contains("demotion"),
        "file absence is not a failure, so no skip note: {stdout}"
    );
}

// T-286: a degraded Edit resolution (old_string not found) means line
// numbers cannot be trusted, so demotion is skipped with a note.
#[test]
fn degraded_edit_resolution_skips_demotion_with_note() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "const a = 1;\n").unwrap();

    let json = edit_json(&file, "not in file", "eval(x);");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "snippet-mode eval must keep blocking; stdout: {stdout}"
    );
    assert!(
        stdout.contains(r#""degraded":true"#),
        "degraded resolution must mark the envelope: {stdout}"
    );
    assert!(
        stdout.contains("demotion skipped"),
        "envelope notes must state demotion was skipped: {stdout}"
    );
}

// T-294: a completed demotion run reports the demoted count in the envelope
// notes without flagging the envelope degraded.
#[test]
fn completed_demotion_reports_count_note_without_degraded() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "eval(old);\nconst a = 1;\n").unwrap();

    let json = edit_json(&file, "const a = 1;", "const a = 2;");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "all blocking violations pre-exist, so exit must be advisory; stdout: {stdout}"
    );
    assert!(
        stdout.contains("diff-aware: 1 pre-existing violation(s) demoted to advisory"),
        "notes must report the demoted count: {stdout}"
    );
    assert!(
        stdout.contains(r#""degraded":false"#),
        "the count note must not flag the envelope degraded: {stdout}"
    );
}

// T-295: when the second pass runs but demotes nothing, the count note still
// appears with zero and the envelope stays non-degraded.
#[test]
fn second_pass_with_zero_demoted_still_reports_count_note() {
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "const a = 1;\n").unwrap();

    let json = edit_json(&file, "const a = 1;", "eval(brandNew);");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the newly added eval must keep blocking; stdout: {stdout}"
    );
    assert!(
        stdout.contains("diff-aware: 0 pre-existing violation(s) demoted to advisory"),
        "notes must report the zero demoted count: {stdout}"
    );
    assert!(
        stdout.contains(r#""degraded":false"#),
        "the count note must not flag the envelope degraded: {stdout}"
    );
}

// T-290: when the before-edit file exists but cannot be read, all blocking
// violations are kept and a note names the read failure.
#[cfg(unix)]
#[test]
fn unreadable_before_file_skips_demotion_and_notes_failure() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tmp_repo_with_claude();
    enable_diff_aware(tmp.path());
    let file = tmp.path().join("app.ts");
    fs::write(&file, "const a = 1;\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();

    let json = write_json(&file, "eval(x);\n");
    let output = run_json(&json, tmp.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unreadable before file must keep eval blocking; stdout: {stdout}"
    );
    assert!(
        stdout.contains("demotion skipped"),
        "envelope notes must state demotion was skipped: {stdout}"
    );
    assert!(
        stdout.contains("permission"),
        "note must name the permission failure: {stdout}"
    );
}
