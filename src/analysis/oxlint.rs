use crate::analysis::react_project;
use crate::config::OxlintConfig;
use crate::download::ensure_oxlint;
use crate::resolve::{run_linter_check, try_resolve_bin, ResolveError};
use crate::rules::{Severity, Violation};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const DEFAULT_DENY_RULES: &[&str] = &[
    "typescript/ban-ts-comment",
    "typescript/no-explicit-any",
    "typescript/no-non-null-assertion",
    "eslint/no-console",
    "eslint/no-new-func",
    // hook 命名の検出先 (#424)。直書きの `--deny` ではなくこのリストに置くのは、
    // `config.allow` が `--allow` を出さずここから差し引くだけで、直書きだと
    // 利用者に無効化手段が残らないため。
    "react/rules-of-hooks",
    // react plugin が既に有効化しているので発火自体は `--deny` 無しでも起きる。
    // ただし oxlint は warning で返し `Severity::Medium` に落ちるため、default の
    // block_threshold では編集が止まらない。`--deny` で error に上げる (#426)。
    "react/jsx-key",
];

// react plugin が道連れに有効化する rule のうち、advisory の量が目立つもの。
// severity は warning なので blocking はしないが、実測した 671 files の診断 71 件
// のうち 69 件をこの 1 本が占めた。
const REACT_RULES_SUPPRESSED: &[&str] = &["react/exhaustive-deps"];

// oxlint default で発火するが guardrails の AST rule が同一 file:line を
// より高い severity / 深い解析で押さえるため、subprocess に `--allow` で
// 抑止指示を渡す rule のリスト。両方が出力すると AI agent から見て同一
// 違反の重複に見え、修正対象の数を誤認させる。
const OXLINT_RULES_OWNED_BY_CUSTOM: &[&str] = &["eslint/no-eval"];

// rules-of-hooks の JSON `code`。CLI / config 側の id (`react/rules-of-hooks`)
// とは別文字列なので、片方を書き換えるときは両方を見る。
const RULES_OF_HOOKS_CODE: &str = "eslint-plugin-react-hooks(rules-of-hooks)";

// rules-of-hooks は `help` を持たず、message は arrow 形の関数を
// `in function "Anonymous"` と呼ぶ。狙う 3 形のうち 2 形が arrow なので、そのまま
// 流すと agent は存在しない Anonymous を改名しようとする。差し替え文は同じ
// message の末尾 2 文で、改名先の形だけを述べている部分。
const RULES_OF_HOOKS_FIX: &str = concat!(
    "React component names must start with an uppercase letter. ",
    "React Hook names must start with the word \"use\"."
);

// rules-of-hooks の宣言行を指すラベル。`labels[0]` は hook の呼び出し行で、
// 改名する宣言行ではない。
const OUTER_FUNCTION_LABEL: &str = "Outer function";

#[derive(Debug, Deserialize)]
struct OxlintOutput {
    diagnostics: Vec<OxlintDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct OxlintDiagnostic {
    message: String,
    // oxlint omits `code` for parse/semantic diagnostics (syntax errors,
    // redeclarations). Optional so one code-less entry does not fail the whole
    // batch deserialize and silently drop every real rule violation (#320).
    code: Option<String>,
    severity: String,
    help: Option<String>,
    #[serde(default)]
    labels: Vec<OxlintLabel>,
}

#[derive(Debug, Deserialize)]
struct OxlintLabel {
    label: Option<String>,
    span: OxlintSpan,
}

#[derive(Debug, Deserialize)]
struct OxlintSpan {
    line: u32,
}

// Reject note wording: state the fact (resolved outside trusted location) and
// the recovery (bundled fallback). Never include "place it under X to use the
// local bin" — that would turn the message into a placement guide for a
// planted binary. The canonical path is logged for forensics but the source
// of the trust boundary is intentionally not spelled out here.
pub fn resolve(file_path: &str, project_root: Option<&Path>) -> (Option<PathBuf>, Vec<String>) {
    match try_resolve_bin("oxlint", file_path, project_root) {
        Ok(path) => (Some(path), Vec::new()),
        Err(ResolveError::NotFound) => (download_bundled(), Vec::new()),
        Err(ResolveError::OutsideProjectRoot { canonical }) => {
            let note = format!(
                "oxlint at {canonical:?} resolved outside trusted location; using bundled fallback"
            );
            eprintln!("guardrails: {note}");
            (download_bundled(), vec![note])
        }
    }
}

fn download_bundled() -> Option<PathBuf> {
    ensure_oxlint()
        .inspect_err(|e| eprintln!("guardrails: oxlint unavailable: {e}"))
        .ok()
}

pub fn check(
    content: &str,
    file_path: &str,
    bin: &Path,
    config: &OxlintConfig,
) -> Option<Vec<Violation>> {
    let args = build_args(config, react_project::is_react_project(file_path));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output: OxlintOutput = run_linter_check(content, file_path, bin, &arg_refs, "oxlint")?;
    Some(convert_diagnostics(output, file_path))
}

fn build_args(config: &OxlintConfig, enable_react_plugin: bool) -> Vec<String> {
    let mut args = vec!["--format".to_owned(), "json".to_owned()];

    // react plugin は default off。`--deny react/rules-of-hooks` だけを渡すと
    // 診断ゼロの無言通過になるので、この flag と対で出す。
    if enable_react_plugin {
        args.push("--react-plugin".to_owned());
        // 抑止は deny ループより「前」。oxlint は rule 同士で last-wins なので、
        // 後ろだと利用者自身の `oxlint.deny` を上書きしてしまう。下の
        // OXLINT_RULES_OWNED_BY_CUSTOM が deny の「後」なのは、逆に利用者の deny
        // に勝たせる意図による。
        for rule in REACT_RULES_SUPPRESSED {
            args.push("--allow".to_owned());
            args.push((*rule).to_owned());
        }
    }

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

    for rule in OXLINT_RULES_OWNED_BY_CUSTOM {
        args.push("--allow".to_owned());
        args.push((*rule).to_owned());
    }

    args
}

fn convert_diagnostics(output: OxlintOutput, file_path: &str) -> Vec<Violation> {
    output
        .diagnostics
        .into_iter()
        .filter_map(|d| {
            // code-less diagnostics are oxlint's own parse/semantic errors, not
            // rule violations; skip them so the real violations in the same
            // batch still surface (#320).
            let code = d.code?;
            let severity = Severity::from_linter_str(&d.severity);
            let is_rules_of_hooks = code == RULES_OF_HOOKS_CODE;

            let line = d
                .labels
                .iter()
                .find(|l| is_rules_of_hooks && l.label.as_deref() == Some(OUTER_FUNCTION_LABEL))
                .or_else(|| d.labels.first())
                .map(|l| l.span.line);

            let fix = if is_rules_of_hooks {
                RULES_OF_HOOKS_FIX.to_owned()
            } else {
                d.help.unwrap_or(d.message)
            };

            Some(Violation {
                rule: format!("oxlint/{code}"),
                severity,
                fix,
                file: file_path.to_owned(),
                line,
                origin: None,
            })
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

    // T-320 (#320): synthetic unit test for the deserialize/filter contract,
    // not a reproduction of real oxlint output. Under guardrails' args oxlint
    // stops linting on a parse/semantic error and emits the code-less
    // diagnostic alone — it does not co-batch a code-less entry with coded
    // violations (that needs `--report-unused-disable-directives`, which
    // guardrails never passes). This pins the contract anyway: a code-less
    // entry deserializes (was `code: String` → whole-batch deserialize
    // failure) and is filtered out, while any coded violation in the same
    // batch survives. Guards against a future oxlint / arg change that does
    // co-batch them.
    #[test]
    fn codeless_diagnostic_is_skipped_real_violations_survive() {
        let json = r#"{"diagnostics": [
            {
                "message": "Unexpected token",
                "severity": "error",
                "labels": [{"span": {"offset": 0, "length": 1, "line": 1, "column": 1}}]
            },
            {
                "message": "Unexpected console statement",
                "code": "eslint(no-console)",
                "severity": "error",
                "help": "Delete this console statement",
                "labels": [{"span": {"offset": 20, "length": 11, "line": 3, "column": 1}}]
            }
        ]}"#;

        let violations = parse_diagnostics(json, "f.ts");
        assert_eq!(
            violations.len(),
            1,
            "code-less diagnostic must be skipped while the real violation is kept"
        );
        assert_eq!(violations[0].rule, "oxlint/eslint(no-console)");
        assert_eq!(violations[0].line, Some(3));
    }

    // 実測した oxlint 1.56.0 の出力から、`help` 欠落と 2 本のラベルを残したもの。
    const RULES_OF_HOOKS_JSON: &str = r#"{"diagnostics": [{
        "message": "React Hook \"useState\" is called in function \"Anonymous\" that is neither a React function component nor a custom React Hook function. React component names must start with an uppercase letter. React Hook names must start with the word \"use\".",
        "code": "eslint-plugin-react-hooks(rules-of-hooks)",
        "severity": "error",
        "labels": [
            {"label": "Hook is called here", "span": {"offset": 79, "length": 8, "line": 7, "column": 46}},
            {"label": "Outer function", "span": {"offset": 59, "length": 44, "line": 3, "column": 26}}
        ]
    }]}"#;

    // T-436 (#424)
    #[test]
    fn replaces_the_rules_of_hooks_fix_text_so_it_never_names_the_function_anonymous() {
        let violations = parse_diagnostics(RULES_OF_HOOKS_JSON, "/src/hooks/useFetch.ts");
        // agent が読む文面そのものなので完全一致で固定する。部分一致だと連結時の
        // 余分な空白や欠けた文が素通りする。
        assert_eq!(
            violations[0].fix,
            "React component names must start with an uppercase letter. \
             React Hook names must start with the word \"use\"."
        );
    }

    // T-437 (#424)
    #[test]
    fn takes_the_rules_of_hooks_line_from_the_outer_function_label_instead_of_the_first_label() {
        let violations = parse_diagnostics(RULES_OF_HOOKS_JSON, "/src/hooks/useFetch.ts");
        assert_eq!(violations[0].line, Some(3));
    }

    // T-438 (#424)
    #[test]
    fn keeps_the_first_label_line_and_the_help_then_message_fallback_for_every_other_rule() {
        let json = r#"{"diagnostics": [{
            "message": "Unexpected console statement",
            "code": "eslint(no-console)",
            "severity": "error",
            "help": "Delete this console statement",
            "labels": [
                {"label": "Hook is called here", "span": {"offset": 0, "length": 1, "line": 9, "column": 1}},
                {"label": "Outer function", "span": {"offset": 0, "length": 1, "line": 2, "column": 1}}
            ]
        }]}"#;
        let violations = parse_diagnostics(json, "/src/app.ts");
        assert_eq!(violations[0].fix, "Delete this console statement");
        assert_eq!(violations[0].line, Some(9));
    }

    fn deny_count(args: &[String]) -> usize {
        args.windows(2).filter(|w| w[0] == "--deny").count()
    }

    // T-007: default config → 7 deny flags
    #[test]
    fn build_args_default_has_seven_deny() {
        let config = OxlintConfig::default();
        let args = build_args(&config, false);
        assert_eq!(deny_count(&args), 7);
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
        let args = build_args(&config, false);
        assert_eq!(deny_count(&args), 8);
        assert!(args.contains(&"eslint/curly".to_owned()));
    }

    // T-009: allow removes from defaults
    #[test]
    fn build_args_allow_removes_from_defaults() {
        let config = OxlintConfig {
            deny: vec![],
            allow: vec!["eslint/no-console".to_owned()],
        };
        let args = build_args(&config, false);
        assert_eq!(deny_count(&args), 6);
        assert!(!args.contains(&"eslint/no-console".to_owned()));
    }

    // T-446 (#426): jsx-key が list に載っていること自体の pin。
    #[test]
    fn denies_jsx_key_by_default_to_raise_it_from_warning_to_error() {
        let args = build_args(&OxlintConfig::default(), true);
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--deny" && w[1] == "react/jsx-key"),
            "expected `--deny react/jsx-key`; without it oxlint returns warning and the \
             edit is not stopped. got: {args:?}"
        );
    }

    // T-432 (#424)
    #[test]
    fn emits_react_plugin_when_the_file_belongs_to_a_react_project() {
        let args = build_args(&OxlintConfig::default(), true);
        assert!(
            args.contains(&"--react-plugin".to_owned()),
            "react plugin is default off, so rules-of-hooks stays silent without this flag; got: {args:?}"
        );
    }

    // T-433 (#424)
    #[test]
    fn omits_react_plugin_when_the_file_does_not_belong_to_a_react_project() {
        let args = build_args(&OxlintConfig::default(), false);
        assert!(
            !args.contains(&"--react-plugin".to_owned()),
            "Vue/Nuxt の composable は .ts に住み rules-of-hooks に誤検知される; got: {args:?}"
        );
    }

    // T-434 (#424)
    #[test]
    fn omits_deny_rules_of_hooks_when_the_user_allows_that_rule_in_config() {
        let config = OxlintConfig {
            deny: vec![],
            allow: vec!["react/rules-of-hooks".to_owned()],
        };
        let args = build_args(&config, true);
        assert!(
            !args
                .windows(2)
                .any(|w| w[0] == "--deny" && w[1] == "react/rules-of-hooks"),
            "expected the user allow to remove the default deny; got: {args:?}"
        );
    }

    // T-435 (#424)
    #[test]
    fn emits_allow_exhaustive_deps_before_the_first_deny_so_a_user_deny_still_wins() {
        let config = OxlintConfig {
            deny: vec!["react/exhaustive-deps".to_owned()],
            allow: vec![],
        };
        let args = build_args(&config, true);
        let allow_idx = args
            .windows(2)
            .position(|w| w[0] == "--allow" && w[1] == "react/exhaustive-deps")
            .unwrap_or_else(|| {
                panic!("expected `--allow react/exhaustive-deps` in args: {args:?}")
            });
        let deny_idx = args
            .windows(2)
            .position(|w| w[0] == "--deny")
            .unwrap_or_else(|| panic!("expected at least one `--deny` in args: {args:?}"));
        assert!(
            allow_idx < deny_idx,
            "expected the suppression before every --deny so a user deny wins by last-wins; got args: {args:?}"
        );
    }

    // T-081: oxlint default `no-eval` is suppressed so it does not duplicate the
    // custom AST `eval` rule (issue #124).
    #[test]
    fn build_args_allows_eval_to_defer_to_custom_rule() {
        let config = OxlintConfig::default();
        let args = build_args(&config, false);
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--allow" && w[1] == "eslint/no-eval"),
            "expected `--allow eslint/no-eval` so oxlint defers eval to the custom rule, got: {args:?}"
        );
    }

    // T-082: user-supplied `config.deny` does not override the overlap allow —
    // the custom rule always owns eval detection. oxlint accumulates rules
    // left-to-right (`-D x -A x` allows; `-A x -D x` denies), so the `--allow`
    // must land after the user `--deny` in the arg list.
    #[test]
    fn build_args_overlap_allow_holds_even_with_user_deny() {
        let config = OxlintConfig {
            deny: vec!["eslint/no-eval".to_owned()],
            allow: vec![],
        };
        let args = build_args(&config, false);
        let deny_idx = args
            .windows(2)
            .position(|w| w[0] == "--deny" && w[1] == "eslint/no-eval")
            .unwrap_or_else(|| panic!("expected `--deny eslint/no-eval` in args: {args:?}"));
        let allow_idx = args
            .windows(2)
            .position(|w| w[0] == "--allow" && w[1] == "eslint/no-eval")
            .unwrap_or_else(|| panic!("expected `--allow eslint/no-eval` in args: {args:?}"));
        assert!(
            allow_idx > deny_idx,
            "expected `--allow eslint/no-eval` to appear after `--deny eslint/no-eval` so oxlint's last-wins rule keeps the custom rule in charge; got args: {args:?}"
        );
    }
}
