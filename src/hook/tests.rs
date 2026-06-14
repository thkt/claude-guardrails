use super::*;
use crate::rules::Severity;

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
        collect_violations("/src/app.ts", "eval(userInput);", &config, None, true);
    assert!(violations.iter().any(|v| v.rule == "eval"));
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
        collect_violations("/src/app.ts", "eval(userInput);", &config, None, true);
    assert!(!violations.iter().any(|v| v.rule == "eval"));
}

#[test]
fn collect_violations_non_js_skips_js_rules() {
    let config = Config::default();
    let (violations, _notes) =
        collect_violations("/README.md", "eval(userInput);", &config, None, false);
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

#[test]
fn collect_violations_no_use_effect_detects_in_tsx() {
    let config = Config::default();
    let (violations, _notes) = collect_violations(
        "/src/App.tsx",
        "useEffect(() => { fetchData(); }, []);",
        &config,
        None,
        true,
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
