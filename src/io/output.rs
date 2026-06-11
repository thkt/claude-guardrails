//! Output rendering for the hook: builds the `ErrorPayload`, writes human
//! stderr lines, and emits the `SuccessEnvelope` / `ErrorEnvelope` JSON when
//! `--json` is enabled.

use crate::config::{Config, ConfigSource, TOOLS_CONFIG_FILE};
use crate::io::color;
use crate::io::envelope::{ErrorCode, ErrorEnvelope, ErrorPayload, SuccessEnvelope};
use crate::io::reporter::{build_json_report, format_violations, format_warnings};
use crate::rules::Violation;
use serde::Serialize;
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
        eprintln!("{}", format_warnings(warnings));
    }
    if !blocking.is_empty() {
        eprintln!("{}", format_violations(blocking));
    }
}

pub(crate) fn print_json_line<T: Serialize>(value: &T) {
    let json = serde_json::to_string(value)
        .expect("print_json_line: envelope serialization is infallible");
    // Ignore write errors (e.g. BrokenPipe) so the caller's exit code is preserved.
    let _ = writeln!(io::stdout().lock(), "{json}");
}

pub(crate) fn emit_json_if_enabled(
    json_mode: bool,
    blocking: &[&Violation],
    warnings: &[&Violation],
    notes: Vec<String>,
    info_notes: Vec<String>,
) {
    if !json_mode {
        return;
    }
    let report = build_json_report(blocking, warnings);
    print_json_line(&SuccessEnvelope::with_notes_and_info(
        report, notes, info_notes,
    ));
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
