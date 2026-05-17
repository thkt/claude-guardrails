use crate::config::OxlintConfig;
use crate::download::ensure_oxlint;
use crate::resolve::{run_linter_check, try_resolve_bin};
use crate::rules::{Severity, Violation};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const DEFAULT_DENY_RULES: &[&str] = &[
    "typescript/ban-ts-comment",
    "typescript/no-explicit-any",
    "typescript/no-non-null-assertion",
    "eslint/no-console",
    "eslint/no-new-func",
];

// oxlint default で発火するが guardrails の AST rule が同一 file:line を
// より高い severity / 深い解析で押さえるため、subprocess に `--allow` で
// 抑止指示を渡す rule のリスト。両方が出力すると AI agent から見て同一
// 違反の重複に見え、修正対象の数を誤認させる。
const OXLINT_OVERLAP_ALLOW: &[&str] = &["eslint/no-eval"];

#[derive(Debug, Deserialize)]
struct OxlintOutput {
    diagnostics: Vec<OxlintDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct OxlintDiagnostic {
    message: String,
    code: String,
    severity: String,
    help: Option<String>,
    #[serde(default)]
    labels: Vec<OxlintLabel>,
}

#[derive(Debug, Deserialize)]
struct OxlintLabel {
    span: OxlintSpan,
}

#[derive(Debug, Deserialize)]
struct OxlintSpan {
    line: u32,
}

pub fn resolve(file_path: &str) -> Option<PathBuf> {
    try_resolve_bin("oxlint", file_path).or_else(|| {
        ensure_oxlint()
            .inspect_err(|e| eprintln!("guardrails: oxlint unavailable: {e}"))
            .ok()
    })
}

pub fn check(
    content: &str,
    file_path: &str,
    bin: &Path,
    config: &OxlintConfig,
) -> Option<Vec<Violation>> {
    let args = build_args(config);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output: OxlintOutput = run_linter_check(content, file_path, bin, &arg_refs, "oxlint")?;
    Some(convert_diagnostics(output, file_path))
}

fn build_args(config: &OxlintConfig) -> Vec<String> {
    let mut args = vec!["--format".to_owned(), "json".to_owned()];

    for rule in DEFAULT_DENY_RULES
        .iter()
        .map(ToString::to_string)
        .chain(config.deny.iter().cloned())
    {
        if !config.allow.contains(&rule) {
            args.push("--deny".to_owned());
            args.push(rule);
        }
    }

    for rule in OXLINT_OVERLAP_ALLOW {
        args.push("--allow".to_owned());
        args.push((*rule).to_owned());
    }

    args
}

fn convert_diagnostics(output: OxlintOutput, file_path: &str) -> Vec<Violation> {
    output
        .diagnostics
        .into_iter()
        .map(|d| {
            let severity = Severity::from_linter_str(&d.severity);

            Violation {
                rule: format!("oxlint/{}", d.code),
                severity,
                fix: d.help.unwrap_or(d.message),
                file: file_path.to_owned(),
                line: d.labels.first().map(|l| l.span.line),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_diagnostics(json: &str, file_path: &str) -> Vec<Violation> {
        let output: OxlintOutput = serde_json::from_str(json).unwrap();
        convert_diagnostics(output, file_path)
    }

    #[test]
    fn parse_single_diagnostic() {
        let json = r#"{
            "diagnostics": [{
                "message": "`debugger` statement is not allowed",
                "code": "eslint(no-debugger)",
                "severity": "error",
                "causes": [],
                "url": "https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-debugger.html",
                "help": "Remove the debugger statement",
                "filename": "test.js",
                "labels": [{"span": {"offset": 38, "length": 9, "line": 5, "column": 1}}],
                "related": []
            }],
            "number_of_files": 1,
            "number_of_rules": 2,
            "threads_count": 1,
            "start_time": 0.018
        }"#;

        let violations = parse_diagnostics(json, "test.js");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "oxlint/eslint(no-debugger)");
        assert_eq!(violations[0].severity, Severity::High);
        assert_eq!(violations[0].fix, "Remove the debugger statement");
        assert_eq!(violations[0].line, Some(5));
        assert_eq!(violations[0].file, "test.js");
    }

    #[test]
    fn parse_empty_diagnostics() {
        let json = r#"{"diagnostics": [], "number_of_files": 0, "number_of_rules": 0}"#;
        let violations = parse_diagnostics(json, "test.js");
        assert!(violations.is_empty());
    }

    #[test]
    fn help_fallback_to_message() {
        let json = r#"{"diagnostics": [{
            "message": "This is the message",
            "code": "rule",
            "severity": "error",
            "labels": []
        }]}"#;

        let violations = parse_diagnostics(json, "f");
        assert_eq!(violations[0].fix, "This is the message");
    }

    #[test]
    fn no_labels_gives_none_line() {
        let json = r#"{"diagnostics": [{
            "message": "msg",
            "code": "rule",
            "severity": "error",
            "labels": []
        }]}"#;

        let violations = parse_diagnostics(json, "f");
        assert_eq!(violations[0].line, None);
    }

    // T-007: default config → 5 deny flags
    #[test]
    fn build_args_default_has_five_deny() {
        let config = OxlintConfig::default();
        let args = build_args(&config);
        let deny_count = args.windows(2).filter(|w| w[0] == "--deny").count();
        assert_eq!(deny_count, 5);
        assert!(args.contains(&"--format".to_owned()));
        assert!(args.contains(&"json".to_owned()));
    }

    // T-008: custom deny adds to defaults
    #[test]
    fn build_args_custom_deny_adds() {
        let config = OxlintConfig {
            deny: vec!["eslint/curly".to_owned()],
            allow: vec![],
        };
        let args = build_args(&config);
        let deny_count = args.windows(2).filter(|w| w[0] == "--deny").count();
        assert_eq!(deny_count, 6);
        assert!(args.contains(&"eslint/curly".to_owned()));
    }

    // T-009: allow removes from defaults
    #[test]
    fn build_args_allow_removes_from_defaults() {
        let config = OxlintConfig {
            deny: vec![],
            allow: vec!["eslint/no-console".to_owned()],
        };
        let args = build_args(&config);
        let deny_count = args.windows(2).filter(|w| w[0] == "--deny").count();
        assert_eq!(deny_count, 4);
        assert!(!args.contains(&"eslint/no-console".to_owned()));
    }

    // T-081: oxlint default `no-eval` is suppressed so it does not duplicate the
    // custom AST `eval` rule (issue #124).
    #[test]
    fn build_args_allows_eval_to_defer_to_custom_rule() {
        let config = OxlintConfig::default();
        let args = build_args(&config);
        let pair = args
            .windows(2)
            .find(|w| w[0] == "--allow" && w[1] == "eslint/no-eval");
        assert!(
            pair.is_some(),
            "expected `--allow eslint/no-eval` so oxlint defers eval to the custom rule, got: {args:?}"
        );
    }

    // T-082: user-supplied `config.deny` does not override the overlap allow —
    // the custom rule always owns eval detection.
    #[test]
    fn build_args_overlap_allow_holds_even_with_user_deny() {
        let config = OxlintConfig {
            deny: vec!["eslint/no-eval".to_owned()],
            allow: vec![],
        };
        let args = build_args(&config);
        let allow_pair = args
            .windows(2)
            .find(|w| w[0] == "--allow" && w[1] == "eslint/no-eval");
        assert!(
            allow_pair.is_some(),
            "overlap allow must apply even if user adds eslint/no-eval to deny: {args:?}"
        );
    }
}
