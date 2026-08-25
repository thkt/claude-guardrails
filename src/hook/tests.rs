use super::*;
use crate::config::{OverrideEntry, ProjectRulesConfig, RulesConfig, GUARDRAILS_CONFIG_FILE};
use crate::rules::{rule_id, toggle_rule_id_count, Severity};
use globset::Glob;

fn make_violation(rule: &str, severity: Severity) -> Violation {
    Violation {
        rule: rule.to_owned(),
        severity,
        fix: "fix".to_owned(),
        file: "/test.ts".to_owned(),
        line: Some(1),
        origin: None,
        no_demote: None,
    }
}

#[test]
fn collect_violations_detects_eval() {
    let config = Config::default();
    let (violations, _notes) =
        collect_violations("/src/app.ts", "eval(userInput);", &config, None, true, None);
    assert!(violations.iter().any(|v| v.rule == "eval"));
}

// T-11: with `config.rules.invariant=false` the invariant pass is skipped even
// when a mismatching `.invariants.json` and full structured content are present
// (toggle gate at the collect_violations level). No invariant violation fires.
#[test]
fn collect_violations_invariant_toggle_off_skips_gate() {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::write(
        tmp.path().join(".invariants.json"),
        r#"{ "flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();
    let abs = tmp.path().join("flags.json").to_string_lossy().into_owned();

    let mut config = Config::default();
    config.rules.invariant = false;
    config.git_root = Some(tmp.path().to_path_buf());

    let (violations, _notes) = collect_violations(
        &abs,
        r#"{ "checkout": { "v2": true } }"#,
        &config,
        Some(tmp.path()),
        false,
        Some(r#"{ "checkout": { "v2": true } }"#),
    );

    assert_eq!(
        violations
            .iter()
            .filter(|v| v.rule == rule_id::INVARIANT)
            .count(),
        0
    );
}

// T-22: the flagship production chain. A non-JS `.json` Edit flows through
// `get_file_and_content` (which reconstructs `structured_full`) into
// `collect_violations` with the invariant toggle on, and a drifted pinned value
// fires one violation. The split unit tests each verify one half; this joins
// them so a future refactor dropping the `structured_full` argument is caught.
#[test]
fn json_edit_fires_invariant_violation_end_to_end() {
    use crate::content::{get_file_and_content, ToolInput, ToolInputData, ToolName};

    let dir = tempfile::TempDir::new().unwrap();
    // Canonicalize so the macOS `/var` -> `/private/var` symlink does not trip
    // the `starts_with(project_root)` path-traversal guard.
    let root = fs::canonicalize(dir.path()).unwrap();
    let path = root.join("flags.json");
    fs::write(&path, "{\n  \"checkout\": { \"v2\": false }\n}\n").unwrap();
    fs::write(
        root.join(".invariants.json"),
        r#"{ "flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();

    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("\"v2\": false".to_owned()),
            new_string: Some("\"v2\": true".to_owned()),
            ..ToolInputData::default()
        },
    };

    let target = get_file_and_content(&input, Some(&root)).unwrap();

    let config = Config {
        git_root: Some(root.clone()),
        ..Config::default()
    };

    let (violations, _notes) = collect_violations(
        &target.file_path,
        &target.content,
        &config,
        Some(&root),
        target.is_js,
        target.structured_full.as_full_str(),
    );

    assert_eq!(
        violations
            .iter()
            .filter(|v| v.rule == rule_id::INVARIANT)
            .count(),
        1,
        "non-JS .json Edit must fire exactly one invariant violation through the production chain"
    );
}

// T-29: a `.json` Edit whose on-disk content cannot be reconstructed (here
// non-UTF8 bytes) reaches `run_hook_with_input` as a Degraded structured_full.
// When the file is pinned, the gate must fail open (exit 0, advisory note) rather
// than block, exercising the degraded-note wiring around the invariant pass.
#[test]
fn json_edit_degraded_content_fails_open_with_note() {
    use crate::content::{ToolInput, ToolInputData, ToolName};

    let dir = tempfile::TempDir::new().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let path = root.join("flags.json");
    // Invalid UTF-8 on disk -> reconstruct_structured_full returns Degraded.
    fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
    fs::write(
        root.join(".invariants.json"),
        r#"{ "flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();

    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("checkout".to_owned()),
            new_string: Some("checkout-edited".to_owned()),
            ..ToolInputData::default()
        },
    };

    let root_for_config = root.clone();
    let exit = run_hook_with_input(
        &input,
        Ok(root.clone()),
        || {
            Ok((
                Config {
                    git_root: Some(root_for_config),
                    ..Config::default()
                },
                Vec::new(),
            ))
        },
        false,
    );

    assert_eq!(
        exit, 0,
        "degraded pinned .json edit must fail open (advisory), not block"
    );
}

// T-533: `config_guard` judges by `file_path` alone and never reads `content`,
// so reaching `collect_violations` at all decides whether it fires.
#[test]
fn guardrails_json_から行を削る空_new_string_の_edit_が_critical_の_violation_になる() {
    use crate::content::{get_file_and_content, ToolInput, ToolInputData, ToolName};

    let dir = tempfile::TempDir::new().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let path = root.join(".guardrails.json");
    fs::write(&path, "{\n  \"rules\": { \"eval\": true }\n}\n").unwrap();

    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("\"rules\": { \"eval\": true }".to_owned()),
            new_string: Some(String::new()),
            ..ToolInputData::default()
        },
    };

    let target = get_file_and_content(&input, Some(&root))
        .expect("empty new_string deletion on .guardrails.json must still resolve a target");

    let config = Config {
        git_root: Some(root.clone()),
        ..Config::default()
    };

    let (violations, _notes) = collect_violations(
        &target.file_path,
        &target.content,
        &config,
        Some(&root),
        target.is_js,
        target.structured_full.as_full_str(),
    );

    let hit = violations
        .iter()
        .find(|v| v.rule == rule_id::CONFIG_GUARD)
        .unwrap_or_else(|| panic!("config_guard must fire; got: {violations:?}"));
    assert_eq!(hit.severity, Severity::Critical);
}

// T-534: `run_invariant_pass` reads `structured_full`, not the Edit snippet,
// so an emptied snippet still carries the deleted pin into the gate.
#[test]
fn pin_済みの_json_から値を削る空_new_string_の_edit_が_invariant_gate_に届く() {
    use crate::content::{get_file_and_content, ToolInput, ToolInputData, ToolName};

    let dir = tempfile::TempDir::new().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let path = root.join("flags.json");
    fs::write(&path, "{\n  \"checkout\": { \"v2\": false }\n}\n").unwrap();
    fs::write(
        root.join(".invariants.json"),
        r#"{ "flags.json": { "checkout.v2": false } }"#,
    )
    .unwrap();

    let input = ToolInput {
        tool_name: ToolName::Edit,
        tool_input: ToolInputData {
            file_path: Some(path.to_string_lossy().into_owned()),
            old_string: Some("\"v2\": false".to_owned()),
            new_string: Some(String::new()),
            ..ToolInputData::default()
        },
    };

    let target = get_file_and_content(&input, Some(&root)).expect(
        "empty new_string deletion of a pinned value on a reconstructable .json file must still resolve",
    );

    let config = Config {
        git_root: Some(root.clone()),
        ..Config::default()
    };

    let (violations, _notes) = collect_violations(
        &target.file_path,
        &target.content,
        &config,
        Some(&root),
        target.is_js,
        target.structured_full.as_full_str(),
    );

    assert!(
        violations.iter().any(|v| v.rule == rule_id::INVARIANT),
        "deleting a pinned value via empty new_string must reach the invariant gate; got: {violations:?}"
    );
}

#[test]
fn collect_violations_clean_code() {
    let config = Config::default();
    let (violations, _notes) = collect_violations(
        "/src/app.ts",
        "export function main() {}\n",
        &config,
        None,
        true,
        None,
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );
}

#[test]
fn collect_violations_disabled_rule_skipped() {
    let mut config = Config::default();
    config.rules.eval = false;
    let (violations, _notes) =
        collect_violations("/src/app.ts", "eval(userInput);", &config, None, true, None);
    assert!(!violations.iter().any(|v| v.rule == "eval"));
}

#[test]
fn collect_violations_non_js_skips_js_rules() {
    let config = Config::default();
    let (violations, _notes) =
        collect_violations("/README.md", "eval(userInput);", &config, None, false, None);
    assert!(!violations.iter().any(|v| v.rule == "eval"));
}

#[test]
fn collect_violations_ast_security_detects_injection() {
    let config = Config::default();
    let (violations, _notes) = collect_violations(
        "/src/app/api/users/route.ts",
        "exec(userInput);",
        &config,
        None,
        true,
        None,
    );
    assert!(violations
        .iter()
        .any(|v| v.rule == "child-process-injection"));
}

#[test]
fn collect_violations_ast_security_disabled() {
    let mut config = Config::default();
    config.rules.ast_security = false;
    let (violations, _notes) = collect_violations(
        "/src/app/api/users/route.ts",
        "exec(userInput);",
        &config,
        None,
        true,
        None,
    );
    assert!(!violations
        .iter()
        .any(|v| v.rule == "child-process-injection"));
}

// #294 regression guard at the production-wiring level: check_bidi must run
// even when oxc parse fails. The unterminated string makes the parser panic, so
// `with_parsed_program` returns None — the "parse failed" note confirms the
// fail-open path was taken, and the bidi violation must still be reported. If a
// future change re-traps check_bidi inside the parse closure, this fails (the
// unit suite would otherwise miss it; the CLI test alone would catch it).
#[test]
fn collect_violations_bidi_detected_when_parse_fails() {
    let config = Config::default();
    let (violations, notes) = collect_violations(
        "/src/app.ts",
        "const x = \"\u{202E}\nfoo",
        &config,
        None,
        true,
        None,
    );
    assert!(
        notes.iter().any(|n| n.contains("parse failed")),
        "expected parse-failure note (confirms fail-open path); notes: {notes:?}"
    );
    assert!(
        violations.iter().any(|v| v.rule == "bidi-characters"),
        "bidi must be detected despite parse failure; got: {violations:?}"
    );
}

// #314 regression at the production-wiring level: deep nesting must produce a
// High excessive-nesting violation that routes to blocking (exit 2) instead of
// overflowing the parser stack and aborting (exit 134 = fail-open). Depth 150 is
// above the guard threshold but below the parse overflow floor, so a guard
// regression fails this assertion cleanly instead of aborting the test runner.
// The before-parse timing is pinned by the CLI test `deep_nesting_exits_two_not_aborts`
// (depth 5000 would abort with 134 if the parse ran).
#[test]
fn collect_violations_deep_nesting_blocks_before_parse() {
    let config = Config::default();
    let src = format!("const x = {}1{};", "(".repeat(150), ")".repeat(150));
    let (violations, _notes) = collect_violations("/src/app.ts", &src, &config, None, true, None);
    assert!(
        violations
            .iter()
            .any(|v| v.rule == "excessive-nesting" && v.severity == Severity::High),
        "deep nesting must produce a High excessive-nesting violation; got: {violations:?}"
    );
    let (blocking, _warnings) = partition_violations(violations, &config);
    assert!(
        blocking.iter().any(|v| v.rule == "excessive-nesting"),
        "High excessive-nesting must route to blocking (exit 2)"
    );
}

// #314: the guard protects the parse, which fires whenever ANY AST rule is on
// — not just ast_security. With ast_security off but eval still on, the parse
// would run, so the guard must still block the deep input.
#[test]
fn collect_violations_deep_nesting_blocks_when_ast_security_disabled_but_parse_runs() {
    let mut config = Config::default();
    config.rules.ast_security = false;
    let src = format!("const x = {}1{};", "(".repeat(150), ")".repeat(150));
    let (violations, _notes) = collect_violations("/src/app.ts", &src, &config, None, true, None);
    assert!(
        violations
            .iter()
            .any(|v| v.rule == "excessive-nesting" && v.severity == Severity::High),
        "guard must fire while the parse it protects can still run; got: {violations:?}"
    );
}

// #314: when every AST rule is off, the parse is skipped entirely, so the guard
// that exists only to protect that parse is moot and must not fire.
#[test]
fn collect_violations_deep_nesting_skipped_when_all_ast_rules_disabled() {
    let mut config = Config::default();
    config.rules.ast_security = false;
    config.rules.no_use_effect = false;
    config.rules.open_redirect = false;
    config.rules.eval = false;
    config.rules.sqli_concat = false;
    config.rules.cors_wildcard = false;
    config.rules.test_assertion = false;
    let src = format!("const x = {}1{};", "(".repeat(150), ")".repeat(150));
    let (violations, _notes) = collect_violations("/src/app.ts", &src, &config, None, true, None);
    assert!(!violations.iter().any(|v| v.rule == "excessive-nesting"));
}

#[test]
fn collect_violations_no_use_effect_detects_in_tsx() {
    let config = Config::default();
    let (violations, _notes) = collect_violations(
        "/src/App.tsx",
        "useEffect(() => { fetchData(); }, []);",
        &config,
        None,
        true,
        None,
    );
    assert!(violations.iter().any(|v| v.rule == "no-use-effect"));
}

#[test]
fn collect_violations_no_use_effect_disabled() {
    let mut config = Config::default();
    config.rules.no_use_effect = false;
    let (violations, _notes) = collect_violations(
        "/src/App.tsx",
        "useEffect(() => { fetchData(); }, []);",
        &config,
        None,
        true,
        None,
    );
    assert!(!violations.iter().any(|v| v.rule == "no-use-effect"));
}

#[test]
fn partition_default_severity_routing() {
    let config = Config::default();
    for (severity, expect_block) in [
        (Severity::Critical, true),
        (Severity::High, true),
        (Severity::Medium, false),
    ] {
        let violations = vec![make_violation("test", severity)];
        let (blocking, warnings) = partition_violations(violations, &config);
        assert_eq!(
            !blocking.is_empty(),
            expect_block,
            "{severity:?} should {}",
            if expect_block { "block" } else { "warn" }
        );
        assert_eq!(
            !warnings.is_empty(),
            !expect_block,
            "{severity:?} should {}",
            if expect_block { "block" } else { "warn" }
        );
    }
}

#[test]
fn partition_custom_block_threshold() {
    let mut config = Config::default();
    config.severity.block_threshold = Severity::Medium;
    let violations = vec![
        make_violation("high-rule", Severity::High),
        make_violation("medium-rule", Severity::Medium),
        make_violation("low-rule", Severity::Low),
    ];
    let (blocking, warnings) = partition_violations(violations, &config);
    // threshold Medium: Medium and above (High) block, Low warns.
    assert_eq!(blocking.len(), 2);
    assert!(blocking.iter().any(|v| v.rule == "high-rule"));
    assert!(blocking.iter().any(|v| v.rule == "medium-rule"));
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].rule, "low-rule");
}

#[test]
fn partition_empty_violations() {
    let config = Config::default();
    let violations: Vec<Violation> = vec![];
    let (blocking, warnings) = partition_violations(violations, &config);
    assert!(blocking.is_empty());
    assert!(warnings.is_empty());
}

#[test]
fn resolve_project_root_or_note_returns_path_and_skips_notes_on_ok() {
    let mut notes = Vec::new();
    let path = PathBuf::from("/some/path");
    let result = resolve_project_root_or_note(Ok(path.clone()), &mut notes);
    assert_eq!(result, Some(path));
    assert!(notes.is_empty(), "no note expected on Ok, got: {notes:?}");
}

#[test]
fn resolve_project_root_or_note_pushes_note_on_err() {
    let mut notes = Vec::new();
    let err = io::Error::new(io::ErrorKind::NotFound, "no such dir");
    let result = resolve_project_root_or_note(Err(err), &mut notes);
    assert!(result.is_none(), "expected None on Err, got: {result:?}");
    assert_eq!(notes.len(), 1, "expected one note, got: {notes:?}");
    assert!(
        notes[0].contains("cannot resolve project root"),
        "note must describe failure; got: {}",
        notes[0]
    );
    assert!(
        notes[0].contains("no such dir"),
        "note must include underlying error; got: {}",
        notes[0]
    );
}

#[test]
fn load_config_or_note_returns_config_and_skips_notes_on_ok() {
    let mut notes = Vec::new();
    let result = load_config_or_note(Ok((Config::default(), Vec::new())), &mut notes);
    assert!(result.enabled);
    assert!(notes.is_empty(), "no note expected on Ok, got: {notes:?}");
}

#[test]
fn load_config_or_note_pushes_note_and_falls_back_to_default_on_err() {
    let mut notes = Vec::new();
    let result = load_config_or_note(
        Err(ConfigError::Parse {
            path: PathBuf::from("x"),
            source: serde_json::from_str::<serde_json::Value>("!").unwrap_err(),
        }),
        &mut notes,
    );
    assert!(result.enabled, "fallback must be Config::default()");
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0].contains("config error"),
        "note must describe failure; got: {}",
        notes[0]
    );
    assert!(
        notes[0].contains("invalid config"),
        "note must include underlying error; got: {}",
        notes[0]
    );
}

// The three below pin what one resolution point has to cover: a registry rule,
// a rule gated outside the registry, and the note. Why that point is the right
// one lives on `resolve_effective_rules_with_notes` in `src/hook.rs`.

// T-459: override がマッチするパスでは registry 経由の rule が発火しない
#[test]
fn override_がマッチするパスでは_registry_経由の_rule_が発火しない() {
    let file_path = "/project/.env";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig =
        serde_json::from_str(r#"{"sensitiveFile": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(file_path).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    let (violations, _notes) = collect_violations(
        file_path,
        "DB_URL=postgres://localhost/db\n",
        &resolved,
        None,
        false,
        None,
    );
    assert!(
        !violations.iter().any(|v| v.rule == rule_id::SENSITIVE_FILE),
        "sensitive-file must not fire once the matching override disables it; got: {violations:?}"
    );
}

// T-460: override がマッチするパスでは registry 外で gate される ast_security も発火しない
#[test]
fn override_がマッチするパスでは_registry_外で_gate_される_ast_security_も発火しない() {
    let file_path = "/src/app/api/users/route.ts";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig =
        serde_json::from_str(r#"{"astSecurity": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(file_path).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    let (violations, _notes) =
        collect_violations(file_path, "exec(userInput);", &resolved, None, true, None);
    assert!(
        !violations
            .iter()
            .any(|v| v.rule == rule_id::CHILD_PROCESS_INJECTION),
        "child-process-injection (gated by ast_security, outside rules::load_rules) must not \
         fire once the matching override disables ast_security; got: {violations:?}"
    );
}

// T-461: override が rule を無効化すると無効化された rule 名と一致した pattern を含む note が積まれる
#[test]
fn override_が_rule_を無効化すると無効化された_rule_名と一致した_pattern_を含む_note_が積まれる() {
    let file_path = "/src/app.ts";
    let pattern = "**/app.ts";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig = serde_json::from_str(r#"{"eval": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(pattern).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let _resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    assert!(
        notes
            .iter()
            .any(|n| n.contains("eval") && n.contains(pattern)),
        "expected a note naming the disabled rule (\"eval\") and the matching override pattern \
         (\"{pattern}\"); got: {notes:?}"
    );
}

// note の `[rule(s)]` / `[pattern(s)]` は角括弧で囲まれるので、数が角括弧の
// 外に出ていることを、中身を除いた文字列で確認する。

/// `[...]` の中身を取り除いた文字列。数が角括弧の外に置かれていることを、
/// rule 名や pattern 文字列に紛れず確認するための helper。
fn strip_bracketed(note: &str) -> String {
    let mut out = String::new();
    let mut depth = 0i32;
    for c in note.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = (depth - 1).max(0),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

// T-502: astSecurity を切る override の note に rule_id 数が入る
#[test]
fn astsecurity_を切る_override_の_note_に_rule_id_数が入る() {
    let file_path = "/src/app/api/users/route.ts";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig =
        serde_json::from_str(r#"{"astSecurity": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(file_path).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let _resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    let expected_count = toggle_rule_id_count("astSecurity", &RulesConfig::default())
        .expect("astSecurity gates a fixed rule_id set");
    let override_note = notes
        .iter()
        .find(|n| n.contains("astSecurity"))
        .unwrap_or_else(|| panic!("expected an override note naming astSecurity; got: {notes:?}"));
    assert!(
        strip_bracketed(override_note).contains(&expected_count.to_string()),
        "expected the stopped rule_id count ({expected_count}) outside the bracketed \
         rule(s)/pattern(s) lists; got: {override_note}"
    );
}

// T-523: 複数の toggle を切る override の note は toggle ごとに数を並べ、合計しない
#[test]
fn 複数の_toggle_を切る_override_の_note_は_toggle_ごとに数を並べる() {
    let file_path = "/src/app.ts";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig =
        serde_json::from_str(r#"{"astSecurity": false, "security": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(file_path).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let _resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    let note = notes
        .iter()
        .find(|n| n.contains("astSecurity"))
        .unwrap_or_else(|| panic!("expected an override note; got: {notes:?}"));
    assert!(
        note.contains("astSecurity stops 14 rule_id(s)"),
        "got: {note}"
    );
    assert!(note.contains("security stops 1 rule_id(s)"), "got: {note}");
    // 14 と 1 が並んでいても、単純合計 (14 + 1 = 15) にはならない。
    assert!(
        !note.contains("15"),
        "counts must not be summed; got: {note}"
    );
}

// T-503: oxlint を切る override の note には数の代わりに外部 linter であることが出る
#[test]
fn oxlint_を切る_override_の_note_には数の代わりに外部_linter_であることが出る() {
    let file_path = "/src/app.ts";
    let pattern = "**/app.ts";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig = serde_json::from_str(r#"{"oxlint": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(pattern).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let _resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    assert_eq!(
        toggle_rule_id_count("oxlint", &RulesConfig::default()),
        None,
        "precondition: oxlint delegates to an external linter run, not a fixed rule_id set"
    );
    let override_note = notes
        .iter()
        .find(|n| n.contains("oxlint"))
        .unwrap_or_else(|| panic!("expected an override note naming oxlint; got: {notes:?}"));
    assert!(
        override_note.to_lowercase().contains("external linter"),
        "expected the note to say oxlint is an external linter instead of a rule_id count; \
         got: {override_note}"
    );
    assert!(
        !strip_bracketed(override_note)
            .chars()
            .any(|c| c.is_ascii_digit()),
        "oxlint gates no fixed rule_id set, so no digit count should appear outside the \
         bracketed rule(s)/pattern(s) lists; got: {override_note}"
    );
}

// T-504: rule_id と 1 対 1 の toggle では数が 1 と出る
#[test]
fn rule_id_と_1_対_1_の_toggle_では数が_1_と出る() {
    let file_path = "/project/.env";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig =
        serde_json::from_str(r#"{"sensitiveFile": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(file_path).unwrap().compile_matcher()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let _resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    let expected_count = toggle_rule_id_count("sensitiveFile", &RulesConfig::default())
        .expect("sensitiveFile gates a fixed rule_id set");
    assert_eq!(
        expected_count, 1,
        "precondition: sensitiveFile is 1:1 with its rule_id (sensitive-file)"
    );
    let override_note = notes
        .iter()
        .find(|n| n.contains("sensitiveFile"))
        .unwrap_or_else(|| {
            panic!("expected an override note naming sensitiveFile; got: {notes:?}")
        });
    assert!(
        strip_bracketed(override_note).contains('1'),
        "expected the stopped rule_id count (1) outside the bracketed rule(s)/pattern(s) \
         lists; got: {override_note}"
    );
}

// --- toggle_rule_id_count(name, rules) ---

// T-604: astSecurity が off の構成で security の数が 2 になる
//
// `rule_id::SECURITY` は `rules.security` と `rules.ast_security` のどちらかが
// on なら live (src/rules.rs の live_rule_ids)。base の astSecurity が既に off
// なら、そこから security も off にすると "security" と "dangerous-inner-html"
// の 2 件とも live_rule_ids から消える。default (astSecurity on) を base にした
// 計算 (現行値 1) と食い違うことを固定する。
#[test]
fn astsecurity_が_off_の構成で_security_の数が_2になる() {
    let mut rules = RulesConfig::default();
    rules.ast_security = false;
    assert_eq!(toggle_rule_id_count("security", &rules), Some(2));
}

// T-511: hook 経路では compile 失敗の note がちょうど 1 件出る
//
// `load_config_or_note` と `resolve_effective_rules_with_notes` を production と
// 同じ順に呼ぶ。読み込み時に 1 回出た note を後段が重ねないことを見る。
#[test]
fn hook_経路では_compile_失敗の_note_がちょうど_1_件出る() {
    let file_path = "/src/app.ts";
    let pattern = "src/[invalid";
    let load_notes = vec![format!(
        "override entry dropped: glob pattern \"{pattern}\" failed to compile in {GUARDRAILS_CONFIG_FILE}"
    )];

    let mut notes = Vec::new();
    let config = load_config_or_note(Ok((Config::default(), load_notes)), &mut notes);
    let _resolved = resolve_effective_rules_with_notes(config, file_path, &mut notes);

    let compile_failure_notes: Vec<&String> = notes
        .iter()
        .filter(|n| n.contains("failed to compile"))
        .collect();
    assert_eq!(
        compile_failure_notes.len(),
        1,
        "expected exactly one compile-failure note through the hook path; got: {notes:?}"
    );
}
