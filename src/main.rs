mod ast;
mod ast_security;
mod color;
mod config;
mod download;
mod oxlint;
mod parse_json;
mod reporter;
mod resolve;
mod rules;
mod scanner;
mod tempfile_util;

use clap::{Parser, Subcommand};
use config::{Config, ConfigSource, TOOLS_CONFIG_FILE};
use reporter::{build_json_report, format_json_report, format_violations, format_warnings};
use rules::{non_comment_lines, Violation, RE_JS_FILE};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

const MAX_INPUT_SIZE: u64 = 10_000_000;
const SYSEXIT_USAGE: i32 = 64;

#[derive(Parser)]
#[command(
    name = "guardrails",
    version,
    about = "Pre-write guardrails for Claude Code (PreToolUse hook)",
    after_help = "\
Hook mode (no subcommand): reads tool input JSON from stdin and emits violations.
With --json: emits a structured JSON report on stdout, human-readable on stderr.

Exit codes:
  0   Pass (no blocking violations) or successful subcommand
  1   I/O error / invalid JSON input / prefetch failure
  2   Blocking violations found (Claude Code halts the tool call)
  64  Usage error (clap parse failure)"
)]
struct Cli {
    /// Emit violations as a structured JSON report on stdout (hook mode only).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Download oxlint binary into the cache (no-op if already present).
    Prefetch,
}

mod tool_name {
    pub const WRITE: &str = "Write";
    pub const EDIT: &str = "Edit";
    pub const MULTI_EDIT: &str = "MultiEdit";
}

#[derive(serde::Deserialize)]
struct ToolInput {
    tool_name: String,
    tool_input: ToolInputData,
}

#[derive(serde::Deserialize)]
struct ToolInputData {
    file_path: Option<String>,
    content: Option<String>,
    new_string: Option<String>,
    edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize)]
struct EditItem {
    new_string: Option<String>,
}

fn get_file_and_content(input: &ToolInput) -> Option<(String, String)> {
    let file_path = input.tool_input.file_path.clone()?;

    let content = match input.tool_name.as_str() {
        tool_name::WRITE => input.tool_input.content.clone()?,
        tool_name::EDIT => input.tool_input.new_string.clone()?,
        tool_name::MULTI_EDIT => {
            let edits = input.tool_input.edits.as_ref()?;
            edits
                .iter()
                .filter_map(|e| e.new_string.clone())
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => {
            if input.tool_input.content.is_some() || input.tool_input.new_string.is_some() {
                eprintln!(
                    "guardrails: unknown tool '{}' has content fields — add to get_file_and_content if it writes files",
                    input.tool_name
                );
            }
            return None;
        }
    };

    if file_path.is_empty() || content.is_empty() {
        return None;
    }

    Some((file_path, content))
}

fn lint_with_external_tools(content: &str, file_path: &str, config: &Config) -> Vec<Violation> {
    if !config.rules.oxlint {
        return Vec::new();
    }

    let Some(bin) = oxlint::resolve(file_path) else {
        if env::var_os("GUARDRAILS_VERBOSE").is_some() {
            eprintln!(
                "guardrails: warning: oxlint not available for {}",
                file_path
            );
        }
        return Vec::new();
    };

    oxlint::check(content, file_path, &bin, &config.oxlint_config).unwrap_or_default()
}

fn lint_with_ast(content: &str, file_path: &str, config: &Config) -> Vec<Violation> {
    ast::with_parsed_program(content, file_path, |program, line_offsets| {
        let mut found = Vec::new();
        if config.rules.ast_security {
            if let Some(v) = ast_security::check_bidi(content, file_path, line_offsets) {
                found.push(v);
            }
            found.extend(ast_security::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if config.rules.no_use_effect {
            found.extend(rules::no_use_effect::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        found
    })
    .unwrap_or_default()
}

fn collect_violations(file_path: &str, content: &str, config: &Config) -> Vec<Violation> {
    let mut violations = Vec::new();
    let is_js = RE_JS_FILE.is_match(file_path);

    if is_js {
        violations.extend(lint_with_external_tools(content, file_path, config));
    }

    let lines = non_comment_lines(content);
    let rules = rules::load_rules(config);
    for rule in &rules {
        if !rule.file_pattern.is_match(file_path) {
            continue;
        }
        violations.extend(rule.check(content, file_path, &lines));
    }

    let has_ast_rules = config.rules.ast_security || config.rules.no_use_effect;
    if is_js && has_ast_rules {
        violations.extend(lint_with_ast(content, file_path, config));
    }

    violations
}

fn partition_violations<'a>(
    violations: &'a [Violation],
    config: &Config,
) -> (Vec<&'a Violation>, Vec<&'a Violation>) {
    violations
        .iter()
        .partition(|v| config.severity.block_on.contains(&v.severity))
}

// Fail-closed: reject oversized input rather than silently truncating.
fn parse_stdin() -> Result<ToolInput, i32> {
    let mut input_str = String::new();
    let bytes_read = io::stdin()
        .take(MAX_INPUT_SIZE + 1)
        .read_to_string(&mut input_str)
        .map_err(|e| {
            eprintln!("guardrails: failed to read stdin: {}", e);
            1
        })?;

    if bytes_read as u64 > MAX_INPUT_SIZE {
        eprintln!(
            "guardrails: input too large (>{} bytes), blocking as precaution",
            MAX_INPUT_SIZE
        );
        return Err(2);
    }

    serde_json::from_str(&input_str).map_err(|e| {
        eprintln!("guardrails: invalid JSON input: {}", e);
        1
    })
}

const DEFAULT_TOOLS_JSON: &str = r#"{"guardrails": {}}
"#;

const CONFIG_HINT_MESSAGE: &str =
    "Guardrails: using defaults. Customize via .claude/tools.json \u{2014} see https://github.com/thkt/guardrails#configuration";

#[derive(Debug, PartialEq)]
enum HintAction {
    Skip,
    Hint,
    CreateAndHint(PathBuf),
}

fn config_hint_action(git_root: &Path, config: &Config) -> HintAction {
    if config.source != ConfigSource::Default {
        return HintAction::Skip;
    }
    let tools_path = git_root.join(TOOLS_CONFIG_FILE);
    if tools_path.exists() {
        return HintAction::Hint;
    }
    let Some(claude_dir) = tools_path.parent() else {
        return HintAction::Skip;
    };
    if claude_dir.is_dir() {
        HintAction::CreateAndHint(tools_path)
    } else {
        HintAction::Skip
    }
}

fn show_config_hint(config: &Config) {
    let Some(ref git_root) = config.git_root else {
        return;
    };
    match config_hint_action(git_root, config) {
        HintAction::Skip => {}
        HintAction::CreateAndHint(path) => {
            if let Err(e) = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .and_then(|mut f| f.write_all(DEFAULT_TOOLS_JSON.as_bytes()))
            {
                eprintln!("guardrails: failed to create {}: {}", path.display(), e);
            }
            eprintln!("{}", color::yellow(CONFIG_HINT_MESSAGE));
        }
        HintAction::Hint => {
            eprintln!("{}", color::yellow(CONFIG_HINT_MESSAGE));
        }
    }
}

fn emit_human_violations(blocking: &[&Violation], warnings: &[&Violation]) {
    if !warnings.is_empty() {
        eprintln!("{}", format_warnings(warnings));
    }
    if !blocking.is_empty() {
        eprintln!("{}", format_violations(blocking));
    }
}

fn emit_json_if_enabled(json_mode: bool, blocking: &[&Violation], warnings: &[&Violation]) {
    if !json_mode {
        return;
    }
    let report = build_json_report(blocking, warnings);
    println!("{}", format_json_report(&report));
}

fn run_prefetch() -> i32 {
    match download::ensure_oxlint() {
        Some(path) => {
            eprintln!("guardrails: oxlint ready at {}", path.display());
            0
        }
        None => {
            eprintln!("guardrails: prefetch failed (network or unsupported platform)");
            1
        }
    }
}

fn run_hook(json_mode: bool) -> i32 {
    let input = match parse_stdin() {
        Ok(v) => v,
        Err(code) => return code,
    };

    let Some((file_path, content)) = get_file_and_content(&input) else {
        let is_write_tool = matches!(
            input.tool_name.as_str(),
            tool_name::WRITE | tool_name::EDIT | tool_name::MULTI_EDIT
        );
        if is_write_tool {
            eprintln!(
                "guardrails: warning: {} has missing or empty file_path/content",
                input.tool_name
            );
        } else {
            eprintln!(
                "guardrails: skipping {} (unsupported tool)",
                input.tool_name
            );
        }
        emit_json_if_enabled(json_mode, &[], &[]);
        return 0;
    };

    let config = match Config::default().with_project_overrides() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "guardrails: config error (using defaults: all rules enabled, block_on=[critical,high]): {}",
                e
            );
            Config::default()
        }
    };

    show_config_hint(&config);

    if !config.enabled {
        emit_json_if_enabled(json_mode, &[], &[]);
        return 0;
    }

    let violations = collect_violations(&file_path, &content, &config);
    let (blocking, warnings) = partition_violations(&violations, &config);

    emit_json_if_enabled(json_mode, &blocking, &warnings);
    emit_human_violations(&blocking, &warnings);
    if blocking.is_empty() {
        0
    } else {
        2
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            let _ = e.print();
            let code = match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => SYSEXIT_USAGE,
            };
            process::exit(code);
        }
    };

    let exit_code = match cli.command {
        Some(Commands::Prefetch) => run_prefetch(),
        None => run_hook(cli.json),
    };
    process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::Severity;

    fn make_write_input(file_path: Option<&str>, content: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name::WRITE.to_owned(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                content: content.map(String::from),
                new_string: None,
                edits: None,
            },
        }
    }

    fn make_edit_input(file_path: Option<&str>, new_string: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name::EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                content: None,
                new_string: new_string.map(String::from),
                edits: None,
            },
        }
    }

    fn make_violation(rule: &str, severity: Severity) -> Violation {
        Violation {
            rule: rule.to_owned(),
            severity,
            fix: "fix".to_owned(),
            file: "/test.ts".to_owned(),
            line: Some(1),
        }
    }

    #[test]
    fn write_extracts_content() {
        let input = make_write_input(Some("/src/app.ts"), Some("const x = 1;"));
        let (path, content) = get_file_and_content(&input).unwrap();
        assert_eq!(path, "/src/app.ts");
        assert_eq!(content, "const x = 1;");
    }

    #[test]
    fn edit_extracts_new_string() {
        let input = make_edit_input(Some("/src/app.ts"), Some("const y = 2;"));
        let (_, content) = get_file_and_content(&input).unwrap();
        assert_eq!(content, "const y = 2;");
    }

    #[test]
    fn multi_edit_joins_edits() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_owned()),
                content: None,
                new_string: None,
                edits: Some(vec![
                    EditItem {
                        new_string: Some("line1".to_owned()),
                    },
                    EditItem {
                        new_string: Some("line2".to_owned()),
                    },
                ]),
            },
        };
        let (_, content) = get_file_and_content(&input).unwrap();
        assert_eq!(content, "line1\nline2");
    }

    #[test]
    fn multi_edit_empty_edits_returns_none() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_owned()),
                content: None,
                new_string: None,
                edits: Some(vec![]),
            },
        };
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn multi_edit_all_none_returns_none() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_owned()),
                content: None,
                new_string: None,
                edits: Some(vec![
                    EditItem { new_string: None },
                    EditItem { new_string: None },
                ]),
            },
        };
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn unsupported_tool_returns_none() {
        let input = ToolInput {
            tool_name: "Bash".to_owned(),
            tool_input: ToolInputData {
                file_path: Some("/tmp/x".to_owned()),
                content: Some("echo hi".to_owned()),
                new_string: None,
                edits: None,
            },
        };
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn invalid_path_or_content_returns_none() {
        for (label, path, content) in [
            ("empty path", Some(""), Some("content")),
            ("empty content", Some("/src/app.ts"), Some("")),
            ("missing path", None, Some("content")),
        ] {
            let input = make_write_input(path, content);
            assert!(get_file_and_content(&input).is_none(), "case: {label}");
        }
    }

    #[test]
    fn collect_violations_detects_eval() {
        let config = Config::default();
        let violations = collect_violations("/src/app.ts", "eval(userInput);", &config);
        assert!(violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_clean_code() {
        let config = Config::default();
        let violations = collect_violations("/src/app.ts", "export function main() {}\n", &config);
        assert!(
            violations.is_empty(),
            "unexpected violations: {:?}",
            violations
        );
    }

    #[test]
    fn collect_violations_disabled_rule_skipped() {
        let mut config = Config::default();
        config.rules.eval = false;
        let violations = collect_violations("/src/app.ts", "eval(userInput);", &config);
        assert!(!violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_non_js_skips_js_rules() {
        let config = Config::default();
        let violations = collect_violations("/README.md", "eval(userInput);", &config);
        assert!(!violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_ast_security_detects_injection() {
        let config = Config::default();
        let violations = collect_violations("/src/app.ts", "exec(userInput);", &config);
        assert!(violations
            .iter()
            .any(|v| v.rule == "child-process-injection"));
    }

    #[test]
    fn collect_violations_ast_security_disabled() {
        let mut config = Config::default();
        config.rules.ast_security = false;
        let violations = collect_violations("/src/app.ts", "exec(userInput);", &config);
        assert!(!violations
            .iter()
            .any(|v| v.rule == "child-process-injection"));
    }

    #[test]
    fn collect_violations_no_use_effect_detects_in_tsx() {
        let config = Config::default();
        let violations = collect_violations(
            "/src/App.tsx",
            "useEffect(() => { fetchData(); }, []);",
            &config,
        );
        assert!(violations.iter().any(|v| v.rule == "no-use-effect"));
    }

    #[test]
    fn collect_violations_no_use_effect_disabled() {
        let mut config = Config::default();
        config.rules.no_use_effect = false;
        let violations = collect_violations(
            "/src/App.tsx",
            "useEffect(() => { fetchData(); }, []);",
            &config,
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
            let (blocking, warnings) = partition_violations(&violations, &config);
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
    fn partition_custom_block_on() {
        let mut config = Config::default();
        config.severity.block_on = vec![Severity::Medium];
        let violations = vec![
            make_violation("high-rule", Severity::High),
            make_violation("medium-rule", Severity::Medium),
        ];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].rule, "medium-rule");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].rule, "high-rule");
    }

    #[test]
    fn partition_empty_violations() {
        let config = Config::default();
        let violations: Vec<Violation> = vec![];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert!(blocking.is_empty());
        assert!(warnings.is_empty());
    }

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
    fn hint_action_create_when_no_tools_json() {
        let tmp = tmp_with_claude();
        let config = Config::default();
        let expected = HintAction::CreateAndHint(tmp.path().join(TOOLS_CONFIG_FILE));
        assert_eq!(config_hint_action(tmp.path(), &config), expected);
    }

    #[test]
    fn hint_action_hint_when_tools_json_without_guardrails() {
        let tmp = tmp_with_claude();
        fs::write(tmp.path().join(".claude/tools.json"), r#"{"reviews": {}}"#).unwrap();

        let config = Config::default();
        assert_eq!(config_hint_action(tmp.path(), &config), HintAction::Hint);
    }
}
