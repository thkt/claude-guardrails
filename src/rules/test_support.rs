//! Test-only helpers and `rule_id` allowlists shared across rule module tests.
//! Moved verbatim from rules.rs (#284) to keep the production file under 400 lines.
//! Re-exported via glob from rules.rs so existing `super::`/`super::super::`
//! call sites resolve unchanged.

use super::rule_id;
use super::{comment_masked_source, non_comment_lines, Rule, Violation};
use crate::analysis::ast::with_parsed_program;
use oxc_ast::ast::Program;
use std::time::Instant;

/// `security` module だけ 2 `rule_id` (SECURITY / `DANGEROUS_INNER_HTML`) emit する。
pub(crate) const REGISTERED_RULE_IDS: &[&str] = &[
    rule_id::SENSITIVE_FILE,
    rule_id::ARCHITECTURE,
    rule_id::NAMING_CONVENTION,
    rule_id::TRANSACTION_BOUNDARY,
    rule_id::SECURITY,
    rule_id::DANGEROUS_INNER_HTML,
    rule_id::CRYPTO_WEAK,
    rule_id::GENERATED_FILE,
    rule_id::TEST_LOCATION,
    rule_id::DOM_ACCESS,
    rule_id::SYNC_IO,
    rule_id::BUNDLE_SIZE,
    rule_id::FLAKY_TEST,
    rule_id::SENSITIVE_LOGGING,
    rule_id::HARDCODED_SECRET,
    rule_id::HTTP_RESOURCE,
    rule_id::RAW_HTML,
    rule_id::COT_LEAKAGE_MARKER,
    rule_id::SERVICE_WORKER_SCOPE_ROOT,
    rule_id::JWT_CLIENT_DECODE,
];

/// `register_rules!` 経由で load されない `rule_id` の allowlist。emit 元を 1 行で明示する。
pub(crate) const UNREGISTERED_RULE_IDS: &[&str] = &[
    rule_id::BIDI_CHARACTERS,            // ast_security::check_bidi
    rule_id::CHILD_PROCESS_INJECTION,    // ast_security::server_io::check_child_process
    rule_id::CLIENT_ENV_PUBLIC_LEAK,     // ast_security::ssr_env::check_client_env_public_leak
    rule_id::ENV_VAR_FALLBACK,           // ast_security::ssr_env::check_env_var_fallback
    rule_id::ERR_STACK_EXPOSURE,         // ast_security::server_io::check_err_stack
    rule_id::EXCESSIVE_NESTING, // analysis::nesting::check_excessive_nesting (pre-parse guard)
    rule_id::MATH_RANDOM_INSECURE, // ast_security::math_random::check_math_random_*
    rule_id::NON_LITERAL_FS_PATH, // ast_security::server_io::check_fs_path
    rule_id::NON_LITERAL_REQUIRE, // ast_security::server_io::check_non_literal_require
    rule_id::POSTMESSAGE_ORIGIN_MISSING, // ast_security::postmessage::check_{postmessage,onmessage}_origin_missing
    rule_id::PROTOTYPE_POLLUTION, // ast_security::prototype_pollution::check_{prototype_pollution,merge_pollution_sinks}
    rule_id::SSR_SECRET_BLEED,    // ast_security::ssr_env::check_ssr_secret_*
    rule_id::TEST_ENDPOINT_PROD_GUARD, // ast_security::test_route_guard (walk-after emit)
    rule_id::UNSAFE_HTML_INJECTION, // ast_security::html::check_{html_assignment,document_write}
    rule_id::UNSAFE_REGEX,        // ast_security::unsafe_regex::check_unsafe_regex
    rule_id::CORS_WILDCARD,       // main.rs から cors_wildcard::check_program を直接呼ぶ
    rule_id::EVAL,                // ADR-0009 oxlint 委譲、Rust 側は eval::check_program
    rule_id::NO_USE_EFFECT,       // main.rs から no_use_effect::check_program を直接呼ぶ
    rule_id::OPEN_REDIRECT,       // main.rs から open_redirect::check_program を直接呼ぶ
    rule_id::SQLI_CONCAT,         // main.rs から sqli_concat::check_program を直接呼ぶ
    rule_id::TEST_ASSERTION, // test_assertion::check_program (AST 経路、run_ast_rules dispatch)
    rule_id::INVARIANT, // invariant::run_invariant_pass (collect_violations、is_js 非依存の独立パス)
];

pub(in crate::rules) fn check_rule(rule: &Rule, content: &str, file_path: &str) -> Vec<Violation> {
    let masked = comment_masked_source(content);
    rule.check(content, file_path, &non_comment_lines(&masked))
}

/// Test helper for valid fixtures. Panics when no AST is produced (the file
/// type is unsupported or the parser failed). Use `ast_fail_open_check` for
/// tests that assert the production fail-open path.
pub(crate) fn ast_test_check<F>(content: &str, file_path: &str, f: F) -> Vec<Violation>
where
    F: FnOnce(&Program<'_>, &[usize]) -> Vec<Violation>,
{
    with_parsed_program(content, file_path, f)
        .unwrap_or_else(|| panic!("ast_test_check: no AST produced for {file_path}"))
}

/// Test helper that mirrors the production fail-open behavior: returns empty
/// Vec when parsing fails or the file type is unsupported. Use `ast_test_check`
/// for tests that pass valid fixtures.
pub(crate) fn ast_fail_open_check<F>(content: &str, file_path: &str, f: F) -> Vec<Violation>
where
    F: FnOnce(&Program<'_>, &[usize]) -> Vec<Violation>,
{
    with_parsed_program(content, file_path, f).unwrap_or_default()
}

/// Routes a rule's `check_program(program, line_offsets, file_path)` through
/// `ast_test_check`. Rules whose `check_program` needs extra arguments (e.g.,
/// a precomputed import map) construct their own closure instead.
pub(in crate::rules) fn test_check_program<F>(
    content: &str,
    file_path: &str,
    check_fn: F,
) -> Vec<Violation>
where
    F: FnOnce(&Program<'_>, &[usize], &str) -> Vec<Violation>,
{
    ast_test_check(content, file_path, |p, lo| check_fn(p, lo, file_path))
}

/// Fail-open companion to `test_check_program`.
pub(in crate::rules) fn test_check_program_fail_open<F>(
    content: &str,
    file_path: &str,
    check_fn: F,
) -> Vec<Violation>
where
    F: FnOnce(&Program<'_>, &[usize], &str) -> Vec<Violation>,
{
    ast_fail_open_check(content, file_path, |p, lo| check_fn(p, lo, file_path))
}

pub(in crate::rules) fn assert_under_10ms<F>(label: &str, iterations: u128, f: F)
where
    F: Fn(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let per_file_us = elapsed.as_micros() / iterations;
    eprintln!("NFR-001 {label}: {per_file_us}us/file ({iterations} iterations)");
    assert!(
        per_file_us < 10_000,
        "AST {label} check exceeded 10ms/file: {per_file_us}us"
    );
}
