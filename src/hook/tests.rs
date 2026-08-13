use super::*;
use crate::config::{OverrideEntry, ProjectRulesConfig};
use crate::rules::{rule_id, Severity};
use globset::Glob;

fn make_violation(rule: &str, severity: Severity) -> Violation {
    Violation {
        rule: rule.to_owned(),
        severity,
        fix: "fix".to_owned(),
        file: "/test.ts".to_owned(),
        line: Some(1),
        origin: None,
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
            Ok(Config {
                git_root: Some(root_for_config),
                ..Config::default()
            })
        },
        false,
    );

    assert_eq!(
        exit, 0,
        "degraded pinned .json edit must fail open (advisory), not block"
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
    let result = load_config_or_note(Ok(Config::default()), &mut notes);
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

// U-004: `resolve_effective_rules_or_note` sits between `load_config_or_note`
// and `collect_violations` in `run_hook_with_input`, layering
// `Config::effective_rules(file_path)` onto the config's `rules` before the
// pipeline reads any toggle. Because `AstRuleFlags::from_config` and
// `rules::load_rules` both read `config.rules`, resolving once at this single
// point covers a registry rule (`sensitive-file`, via `rules::load_rules`)
// and a rule gated outside the registry (`ast_security`, via
// `AstRuleFlags::from_config` inside `collect_violations`) alike.

// T-459: override がマッチするパスでは registry 経由の rule が発火しない
#[test]
fn override_がマッチするパスでは_registry_経由の_rule_が発火しない() {
    let file_path = "/project/.env";
    let mut config = Config::default();
    let override_rules: ProjectRulesConfig =
        serde_json::from_str(r#"{"sensitiveFile": false}"#).unwrap();
    config.overrides = vec![OverrideEntry {
        files: vec![Glob::new(file_path).unwrap()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let resolved = resolve_effective_rules_or_note(config, file_path, &mut notes);

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
        files: vec![Glob::new(file_path).unwrap()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let resolved = resolve_effective_rules_or_note(config, file_path, &mut notes);

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
        files: vec![Glob::new(pattern).unwrap()],
        rules: override_rules,
    }];

    let mut notes = Vec::new();
    let _resolved = resolve_effective_rules_or_note(config, file_path, &mut notes);

    assert!(
        notes
            .iter()
            .any(|n| n.contains("eval") && n.contains(pattern)),
        "expected a note naming the disabled rule (\"eval\") and the matching override pattern \
         (\"{pattern}\"); got: {notes:?}"
    );
}
