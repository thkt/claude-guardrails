//! Output rendering for the hook: builds the `ErrorPayload`, writes human
//! stderr lines, and emits the `SuccessEnvelope` / `ErrorEnvelope` JSON when
//! `--json` is enabled.

use crate::config::{Config, ConfigSource, TOOLS_CONFIG_FILE};
use crate::io::color;
use crate::io::envelope::{ErrorCode, ErrorEnvelope, ErrorPayload, SuccessEnvelope};
use crate::io::reporter::{build_json_report, format_violations, format_warnings};
use crate::rules::Violation;
use serde::Serialize;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn build_payload(code: ErrorCode, message: String, next_step: &str) -> ErrorPayload {
    ErrorPayload {
        code,
        message,
        next_step: Some(String::from(next_step)),
        candidates: vec![],
        retryable: false,
    }
}

// Side-effecting error render: a stderr line plus the JSON envelope when
// enabled. Exit code is the caller's responsibility (hook input errors map to
// 64 per ADR-0005; prefetch errors use `ErrorCode::exit_code`).
pub(crate) fn render_error(json_mode: bool, payload: ErrorPayload) {
    eprintln!("guardrails: {}", payload.message);
    emit_error_envelope_if_enabled(json_mode, payload);
}

const CONFIG_HINT_MESSAGE: &str =
    "Guardrails: using defaults. Customize via .guardrails.json \u{2014} see https://github.com/thkt/guardrails#configuration";

#[derive(Debug, PartialEq)]
enum HintAction {
    Skip,
    Hint,
}

fn config_hint_action(git_root: &Path, config: &Config) -> HintAction {
    if config.source != ConfigSource::Default {
        return HintAction::Skip;
    }
    let tools_path = git_root.join(TOOLS_CONFIG_FILE);
    if tools_path.exists() || tools_path.parent().is_some_and(Path::is_dir) {
        HintAction::Hint
    } else {
        HintAction::Skip
    }
}

pub(crate) fn show_config_hint(config: &Config) {
    let Some(ref git_root) = config.git_root else {
        return;
    };
    match config_hint_action(git_root, config) {
        HintAction::Skip => {}
        HintAction::Hint => {
            eprintln!("{}", color::yellow(CONFIG_HINT_MESSAGE));
        }
    }
}

pub(crate) fn emit_human_violations(blocking: &[&Violation], warnings: &[&Violation]) {
    if !warnings.is_empty() {
        eprintln!("{}", format_warnings(warnings, color::stderr_takes_color()));
    }
    if !blocking.is_empty() {
        eprintln!("{}", format_violations(blocking));
    }
}

pub(crate) fn print_json_line<T: Serialize>(value: &T) {
    let json = serde_json::to_string(value)
        .expect("print_json_line: envelope serialization is infallible");
    print_line(&json);
}

/// A failed write is not retried: a reader parsing stdout as one document gets
/// nothing from a truncated line, and two fragments from a second attempt.
fn print_line(line: &str) {
    let mut out = io::stdout().lock();
    // Ignore write errors (e.g. BrokenPipe) so the caller's exit code is preserved.
    let _ = out.write_all(format!("{line}\n").as_bytes());
}

/// Claude Code ignores envelope keys it does not recognize, so `data` /
/// `degraded` / `notes` survive alongside `hookSpecificOutput`.
///
/// A new top-level envelope key that the hook output also defines would be read
/// as a hook directive instead of envelope content, so check the current
/// `PreToolUse` output schema before adding one.
#[derive(Serialize)]
struct HookEnvelope<T: Serialize> {
    #[serde(flatten)]
    envelope: SuccessEnvelope<T>,
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    hook_specific_output: Option<HookSpecificOutput>,
}

pub(crate) fn emit_json_if_enabled(
    json_mode: bool,
    blocking: &[&Violation],
    warnings: &[&Violation],
    notes: Vec<String>,
    info_notes: Vec<String>,
    hook_specific_output: Option<HookSpecificOutput>,
) {
    if !json_mode {
        return;
    }
    let report = build_json_report(blocking, warnings);
    print_json_line(&HookEnvelope {
        envelope: SuccessEnvelope::with_notes_and_info(report, notes, info_notes),
        hook_specific_output,
    });
}

/// The hook runs on every edit, so an unbounded list would spend the agent's
/// context on repetition.
const MAX_CONTEXT_VIOLATIONS: usize = 10;

#[derive(Serialize)]
pub(crate) struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "additionalContext")]
    additional_context: String,
}

#[derive(Serialize)]
struct HookOutput<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: &'a HookSpecificOutput,
}

pub(crate) fn emit_hook_context(
    json_mode: bool,
    hook_specific_output: Option<&HookSpecificOutput>,
) {
    if let Some(line) = hook_context_line(json_mode, hook_specific_output) {
        print_line(&line);
    }
}

/// The advisory payload for the agent, `None` when this run has nothing to say.
///
/// A blocking run reaches the agent through the exit-2 stderr path.
pub(crate) fn hook_specific_output(
    blocking: &[&Violation],
    warnings: &[&Violation],
    notes: &[String],
) -> Option<HookSpecificOutput> {
    if !blocking.is_empty() {
        return None;
    }
    if warnings.is_empty() && notes.is_empty() {
        return None;
    }

    let shown: Vec<&Violation> = warnings
        .iter()
        .take(MAX_CONTEXT_VIOLATIONS)
        .copied()
        .collect();
    let mut context = format_warnings(&shown, false).trim_start().to_owned();
    let hidden = warnings.len() - shown.len();
    if hidden > 0 {
        let _ = write!(context, "\n  ... and {hidden} more");
    }
    for note in notes {
        if !context.is_empty() {
            context.push('\n');
        }
        let _ = write!(context, "guardrails: {note}");
    }

    Some(HookSpecificOutput {
        hook_event_name: "PreToolUse",
        additional_context: context,
    })
}

/// Under `--json` the envelope carries the same payload, and two JSON documents
/// on one stream parse as neither.
fn hook_context_line(
    json_mode: bool,
    hook_specific_output: Option<&HookSpecificOutput>,
) -> Option<String> {
    if json_mode {
        return None;
    }
    let output = HookOutput {
        hook_specific_output: hook_specific_output?,
    };
    Some(serde_json::to_string(&output).expect("hook context serialization is infallible"))
}

fn emit_error_envelope_if_enabled(json_mode: bool, payload: ErrorPayload) {
    if !json_mode {
        return;
    }
    print_json_line(&ErrorEnvelope { error: payload });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_with_claude() -> tempfile::TempDir {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".claude")).unwrap();
        tmp
    }

    fn warning(rule: &str) -> Violation {
        Violation {
            rule: rule.to_owned(),
            severity: crate::rules::Severity::Medium,
            fix: format!("fix {rule}"),
            file: "/src/app.ts".to_owned(),
            line: Some(1),
            origin: None,
        }
    }

    fn context_line(
        json_mode: bool,
        blocking: &[&Violation],
        warnings: &[&Violation],
        notes: &[String],
    ) -> Option<String> {
        let output = hook_specific_output(blocking, warnings, notes);
        hook_context_line(json_mode, output.as_ref())
    }

    // T-516: advisory があるとき hook JSON の hookEventName が PreToolUse になる
    #[test]
    fn advisory_があるとき_hook_json_の_hookeventname_が_pretooluse_になる() {
        let v = warning("dom-access");

        let line = context_line(false, &[], &[&v], &[]).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        let context = parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert!(context.contains("dom-access"), "context: {context}");
        assert!(!context.contains('\u{1b}'), "context: {context:?}");
    }

    // T-517: blocking があるとき hook JSON を組まない
    #[test]
    fn blocking_があるとき_hook_json_を組まない() {
        let b = warning("eval");
        let w = warning("dom-access");

        assert!(context_line(false, &[&b], &[&w], &[]).is_none());
    }

    // T-518: json_mode が true のとき単独の hook JSON 行を出さない
    #[test]
    fn json_mode_が_true_のとき単独の_hook_json_行を出さない() {
        let v = warning("dom-access");

        assert!(context_line(true, &[], &[&v], &[]).is_none());
    }

    // T-519: advisory が上限を超えるとき文面に残件数が出る
    #[test]
    fn advisory_が上限を超えるとき文面に残件数が出る() {
        let many: Vec<Violation> = (0..MAX_CONTEXT_VIOLATIONS + 3)
            .map(|i| warning(&format!("rule-{i}")))
            .collect();
        let refs: Vec<&Violation> = many.iter().collect();

        let line = context_line(false, &[], &refs, &[]).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        let context = parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert!(context.contains("3 more"), "context: {context}");
    }

    // note だけでも hook JSON を組む
    #[test]
    fn note_だけでも_hook_json_を組む() {
        let line = context_line(false, &[], &[], &["config note".to_owned()]).unwrap();

        assert!(line.contains("config note"), "line: {line}");
    }

    // 出すものが何も無ければ hook JSON を組まない
    #[test]
    fn 出すものが何も無ければ_hook_json_を組まない() {
        assert!(context_line(false, &[], &[], &[]).is_none());
    }

    fn envelope_json(hook_specific_output: Option<HookSpecificOutput>) -> String {
        serde_json::to_string(&HookEnvelope {
            envelope: SuccessEnvelope::with_notes_and_info(
                serde_json::json!({"violations": []}),
                Vec::new(),
                Vec::new(),
            ),
            hook_specific_output,
        })
        .unwrap()
    }

    // T-543: hook payload があるとき envelope と同じオブジェクトに載る
    #[test]
    fn hook_payload_があるとき_envelope_と同じオブジェクトに載る() {
        let v = warning("dom-access");
        let json = envelope_json(hook_specific_output(&[], &[&v], &[]));

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("data").is_some(), "json: {json}");
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    // T-544: hook payload の有無で envelope のキー順が変わらない
    #[test]
    fn hook_payload_の有無で_envelope_のキー順が変わらない() {
        // 生の文字列で見る。`serde_json::Value` は BTreeMap でキーを並べ替えるため、
        // parse したあとの assert では順序を観測できない。
        let without = envelope_json(None);
        let v = warning("dom-access");
        let with = envelope_json(hook_specific_output(&[], &[&v], &[]));

        let prefix = r#"{"data":{"violations":[]},"degraded":false,"notes":[]"#;
        assert_eq!(without, format!("{prefix}}}"), "without: {without}");
        assert!(with.starts_with(prefix), "with: {with}");
        assert!(with.contains(r#","hookSpecificOutput":{"#), "with: {with}");
    }

    #[test]
    fn hint_action_skip_when_explicit_source() {
        let tmp = tmp_with_claude();
        let config = Config {
            source: ConfigSource::Explicit,
            ..Config::default()
        };
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Skip);
    }

    #[test]
    fn hint_action_skip_when_no_claude_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Skip);
    }

    #[test]
    fn hint_action_hint_when_claude_dir_exists_without_tools_json() {
        let tmp = tmp_with_claude();
        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Hint);
    }

    #[test]
    fn hint_action_hint_when_tools_json_without_guardrails() {
        let tmp = tmp_with_claude();
        fs::write(tmp.path().join(".claude/tools.json"), r#"{"reviews": {}}"#).unwrap();

        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Hint);
    }

    // The hook must not create or write to .claude/tools.json under any code path.
    // After running show_config_hint with a .claude/ present but tools.json absent,
    // the file must remain absent.
    #[test]
    fn hint_does_not_write_tools_json_when_absent() {
        let tmp = tmp_with_claude();
        let tools_path = tmp.path().join(TOOLS_CONFIG_FILE);
        assert!(!tools_path.exists(), "tools.json must be absent before");

        let config = Config {
            source: ConfigSource::Default,
            git_root: Some(tmp.path().to_path_buf()),
            ..Config::default()
        };
        show_config_hint(&config);

        assert!(
            !tools_path.exists(),
            "hook must not create tools.json, but found {}",
            tools_path.display()
        );
    }
}
