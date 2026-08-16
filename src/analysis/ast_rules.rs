//! The seven AST-driven structural rules and the subprocess that runs them
//! (#314). Deeply nested input overflows oxc's recursive-descent parser and
//! aborts the whole process (SIGABRT, exit 134), which is non-blocking for a
//! `PreToolUse` hook — every check is silently bypassed (fail-open). A byte scan
//! catches bracket and prefix-operator nesting before the parse, but JSX and
//! ternary chains overflow with no bracket signature a deterministic scan can
//! see. So the parse and these rules run in a re-exec of this same binary: the
//! child aborts exactly when an in-process parse would, and the parent reads its
//! exit code (signal death) as the overflow signal and emits a blocking
//! Violation. The `cfg!(test)` seam in `hook::lint_with_ast` keeps unit tests on
//! the in-process path (the test binary's entry point cannot dispatch the child
//! subcommand); deep-overflow inputs live only in CLI integration tests.

use crate::analysis::{ast, ast_security};
use crate::config::{Config, RulesConfig};
use crate::import_map;
use crate::rules::{self, Violation};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::panic;
use std::process;

/// The seven toggles that gate an AST rule. Carried to the child so it applies the
/// caller's config without serializing the whole `Config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstRuleFlags {
    pub ast_security: bool,
    pub no_use_effect: bool,
    pub open_redirect: bool,
    pub eval: bool,
    pub sqli_concat: bool,
    pub cors_wildcard: bool,
    pub test_assertion: bool,
}

impl AstRuleFlags {
    /// Reads the seven toggles straight off `RulesConfig`, for callers that hold
    /// only the rules sub-config (not the full `Config`). `from_config` delegates
    /// here so the field ordering lives in one place.
    pub fn from_rules(rules: &RulesConfig) -> Self {
        Self {
            ast_security: rules.ast_security,
            no_use_effect: rules.no_use_effect,
            open_redirect: rules.open_redirect,
            eval: rules.eval,
            sqli_concat: rules.sqli_concat,
            cors_wildcard: rules.cors_wildcard,
            test_assertion: rules.test_assertion,
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::from_rules(&config.rules)
    }

    pub fn any(&self) -> bool {
        self.ast_security
            || self.no_use_effect
            || self.open_redirect
            || self.eval
            || self.sqli_concat
            || self.cors_wildcard
            || self.test_assertion
    }
}

/// The child-subprocess request envelope. A dedicated struct (not `Config`) so
/// only the parse inputs cross the process boundary.
#[derive(Debug, Serialize, Deserialize)]
pub struct AstRequest {
    pub content: String,
    pub file_path: String,
    pub flags: AstRuleFlags,
}

/// Parses `content` and runs the enabled AST rules. Returns None on unsupported
/// file type or parser panic (fail-open, same contract as `with_parsed_program`).
/// A stack overflow inside `.parse()` aborts the process rather than returning —
/// that is the abort the subprocess wrapper isolates.
pub fn run_ast_rules(
    content: &str,
    file_path: &str,
    flags: &AstRuleFlags,
) -> Option<Vec<Violation>> {
    ast::with_parsed_program(content, file_path, |program, line_offsets| {
        let mut found = Vec::new();
        if flags.ast_security {
            found.extend(ast_security::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if flags.no_use_effect {
            found.extend(rules::no_use_effect::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if flags.open_redirect {
            found.extend(rules::open_redirect::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if flags.eval {
            let import_map = import_map::ImportMap::build(program);
            found.extend(rules::eval::check_program(
                program,
                line_offsets,
                file_path,
                &import_map,
            ));
        }
        if flags.sqli_concat {
            found.extend(rules::sqli_concat::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if flags.cors_wildcard {
            found.extend(rules::cors_wildcard::check_program(
                program,
                line_offsets,
                file_path,
            ));
        }
        if flags.test_assertion {
            found.extend(rules::test_assertion::check_program(
                program,
                line_offsets,
                file_path,
                content,
            ));
        }
        found
    })
}

/// Child entry point for the hidden `__ast-child` subcommand. Reads an
/// `AstRequest` from stdin, runs the rules, prints the violations as JSON on
/// stdout. Exit 0 = success (stdout holds the JSON array), exit 1 = parse failed
/// or an envelope/encode error (parent skips structural rules, edit proceeds).
/// A stack overflow aborts the process before any return, so the parent sees
/// neither 0 nor 1 and treats it as the overflow block.
pub fn run_child() -> i32 {
    // Override main()'s exit-70 panic hook: inside the child a panic means the
    // parse failed gracefully (exit 1 = skip structural rules), not an internal
    // invariant breach (exit 70). Stderr is null'd by the parent, so the hook
    // stays silent.
    panic::set_hook(Box::new(|_| process::exit(1)));

    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        return 1;
    }
    let request: AstRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(_) => return 1,
    };
    match run_ast_rules(&request.content, &request.file_path, &request.flags) {
        Some(violations) => match serde_json::to_string(&violations) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(_) => 1,
        },
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    fn all_on() -> AstRuleFlags {
        AstRuleFlags {
            ast_security: true,
            no_use_effect: true,
            open_redirect: true,
            eval: true,
            sqli_concat: true,
            cors_wildcard: true,
            test_assertion: true,
        }
    }

    // The child encodes violations and the parent decodes them: a Violation must
    // survive a JSON round-trip. `origin` is None here and omitted on the wire,
    // so decoding exercises the `serde(default)` that prevents a missing-field
    // failure from silently dropping every structural rule (fail-open).
    #[test]
    fn violation_survives_json_round_trip() {
        let found =
            run_ast_rules("eval(userInput);", "/src/app.ts", &all_on()).expect("valid JS parses");
        let eval = found
            .iter()
            .find(|v| v.rule == "eval")
            .expect("eval rule fires");
        let encoded = serde_json::to_string(eval).expect("encode");
        assert!(
            !encoded.contains("origin"),
            "None origin must stay off the wire; got: {encoded}"
        );
        let decoded: Violation = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.rule, "eval");
        assert_eq!(decoded.severity, Severity::High);
        assert!(decoded.origin.is_none());
    }

    // A whole Vec<Violation> (the child's actual stdout payload) round-trips.
    #[test]
    fn violation_vec_round_trips() {
        let found = run_ast_rules("eval(userInput);", "/src/app.ts", &all_on()).expect("parses");
        let encoded = serde_json::to_string(&found).expect("encode");
        let decoded: Vec<Violation> = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.len(), found.len());
        assert!(decoded.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn unsupported_type_returns_none() {
        assert!(run_ast_rules("body{}", "/styles.css", &all_on()).is_none());
    }

    #[test]
    fn from_config_mirrors_rule_toggles() {
        let mut config = Config::default();
        config.rules.eval = false;
        let flags = AstRuleFlags::from_config(&config);
        assert!(!flags.eval);
        assert!(flags.ast_security);
        assert!(flags.any());
    }

    // T-599
    #[test]
    fn from_rules_は同じ_config_から_from_config_と同じ_flag_集合を返す() {
        let mut config = Config::default();
        config.rules.eval = false;
        config.rules.cors_wildcard = false;

        let from_rules = AstRuleFlags::from_rules(&config.rules);
        let from_config = AstRuleFlags::from_config(&config);

        assert_eq!(from_rules.ast_security, from_config.ast_security);
        assert_eq!(from_rules.no_use_effect, from_config.no_use_effect);
        assert_eq!(from_rules.open_redirect, from_config.open_redirect);
        assert_eq!(from_rules.eval, from_config.eval);
        assert_eq!(from_rules.sqli_concat, from_config.sqli_concat);
        assert_eq!(from_rules.cors_wildcard, from_config.cors_wildcard);
        assert_eq!(from_rules.test_assertion, from_config.test_assertion);
    }
}
