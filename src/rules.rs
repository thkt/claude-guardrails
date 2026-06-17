mod architecture;
mod bundle_size;
pub(crate) mod cors_wildcard;
mod cot_leakage_marker;
mod crypto_weak;
mod dom_access;
pub(crate) mod eval;
mod flaky_test;
mod generated_file;
mod hardcoded_secrets;
mod http_resource;
mod jwt_client;
mod naming;
pub(crate) mod no_use_effect;
pub(crate) mod open_redirect;
mod raw_html;
mod security;
mod sensitive_file;
mod sensitive_logging;
mod service_worker;
pub(crate) mod sqli_concat;
mod sync_io;
pub(crate) mod test_assertion;
mod test_location;
mod transaction;

use crate::analysis::scanner::build_source_masks;
use crate::config::Config;
use crate::regex_compile::regex_or_die;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

/// `rule_id` catalog. 新規 `rule_id` を追加するときは:
///
/// - (a) ここに定数追加 + 単一 module から発火 → `REGISTERED_RULE_IDS` にも追加
/// - (b) `ast_security` 内 / oxlint 委譲 / 別 path 発火 → `UNREGISTERED_RULE_IDS` に追加
///   (各 entry に 1 行 comment 必須)
///
/// 整合性は `tests::rule_id_catalog_entries_match_allowlists` で gate される。
pub(crate) mod rule_id {
    /// 各 `rule_id` を `pub const` と `RULE_ID_CATALOG` (test 専用) に同時定義する macro。
    macro_rules! define_rule_ids {
        ( $( $name:ident = $value:literal ),* $(,)? ) => {
            $( pub const $name: &str = $value; )*
            #[cfg(test)]
            pub(crate) const RULE_ID_CATALOG: &[&str] = &[ $( $name ),* ];
        };
    }

    define_rule_ids! {
        SENSITIVE_FILE = "sensitive-file",
        ARCHITECTURE = "architecture",
        NAMING_CONVENTION = "naming-convention",
        TRANSACTION_BOUNDARY = "transaction-boundary",
        SECURITY = "security",
        CRYPTO_WEAK = "crypto-weak",
        GENERATED_FILE = "generated-file",
        TEST_LOCATION = "test-location",
        DOM_ACCESS = "dom-access",
        SYNC_IO = "sync-io",
        BUNDLE_SIZE = "bundle-size",
        TEST_ASSERTION = "test-assertion",
        FLAKY_TEST = "flaky-test",
        SENSITIVE_LOGGING = "sensitive-logging",
        EVAL = "eval",
        HARDCODED_SECRET = "hardcoded-secret",
        HTTP_RESOURCE = "http-resource",
        RAW_HTML = "raw-html",
        OPEN_REDIRECT = "open-redirect",
        ERR_STACK_EXPOSURE = "err-stack-exposure",
        CHILD_PROCESS_INJECTION = "child-process-injection",
        NO_USE_EFFECT = "no-use-effect",
        NON_LITERAL_FS_PATH = "non-literal-fs-path",
        BIDI_CHARACTERS = "bidi-characters",
        UNSAFE_REGEX = "unsafe-regex",
        NON_LITERAL_REQUIRE = "non-literal-require",
        ENV_VAR_FALLBACK = "env-var-fallback",
        DANGEROUS_INNER_HTML = "dangerous-inner-html",
        MATH_RANDOM_INSECURE = "math-random-insecure",
        COT_LEAKAGE_MARKER = "cot-leakage-marker",
        PROTOTYPE_POLLUTION = "prototype-pollution",
        SQLI_CONCAT = "sqli-concat",
        CORS_WILDCARD = "cors-wildcard",
        UNSAFE_HTML_INJECTION = "unsafe-html-injection",
        SERVICE_WORKER_SCOPE_ROOT = "service-worker-scope-root",
        JWT_CLIENT_DECODE = "jwt-client-decode",
        CLIENT_ENV_PUBLIC_LEAK = "client-env-public-leak",
        SSR_SECRET_BLEED = "ssr-secret-bleed",
        POSTMESSAGE_ORIGIN_MISSING = "postmessage-origin-missing",
        EXCESSIVE_NESTING = "excessive-nesting",
    }
}

pub static RE_JS_FILE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_JS_FILE", r"\.m?[jt]sx?$"));

pub static RE_TEST_FILE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_TEST_FILE", r"\.(test|spec)\.m?[jt]sx?$"));

pub static RE_ALL_FILES: LazyLock<Regex> = LazyLock::new(|| regex_or_die("RE_ALL_FILES", r"."));

pub static RE_REACT_FILE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_REACT_FILE", r"\.(tsx|jsx)$"));

pub const API_PREFIX_PAT: &str = r"(^|/)(app|pages)/api/";

pub static RE_API_FILE: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_API_FILE", API_PREFIX_PAT));

pub static RE_API_OR_MIDDLEWARE_FILE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_API_OR_MIDDLEWARE_FILE",
        &format!("{API_PREFIX_PAT}|(^|/)middleware\\.[jt]sx?$"),
    )
});

pub static RE_API_OR_ROUTE_FILE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_API_OR_ROUTE_FILE",
        &format!("{API_PREFIX_PAT}|(^|/)app/(.*/)?route\\.[jt]sx?$"),
    )
});

/// 1-based line number for a 0-based iteration index. Hook input is capped
/// at `MAX_INPUT_SIZE` bytes far below `u32::MAX` lines, so overflow means the
/// cap broke upstream; fail loudly instead of silently reporting `u32::MAX`.
fn line_number(idx: usize) -> u32 {
    u32::try_from(idx + 1).expect("line count exceeds u32::MAX despite input size cap")
}

/// Lines whose visible (non-whitespace) bytes are not entirely inside comments.
/// Comment classification is delegated to [`build_source_masks`] so string
/// literals containing `/*`/`*/` are not misread as comment markers. Each
/// surviving line is returned as its original full text (zero-copy `&str`).
/// Blank and whitespace-only lines have no visible byte, so they are omitted;
/// callers key on the returned line text (not line-index continuity), so the
/// gaps are inert.
///
/// Perf: this adds a 2nd O(n) scan over `content` (the first being the caller's
/// own parse) plus a `Vec<bool>`/`Vec<u8>` of `content.len()`. Input is bounded
/// by `MAX_INPUT_SIZE` (10 MB) and the NFR budget is <10 ms/file, so the extra
/// pass stays well inside budget; revisit only if dogfooding shows latency.
pub(crate) fn non_comment_lines(content: &str) -> Vec<(u32, &str)> {
    let comment = build_source_masks(content).comment;
    let base = content.as_ptr() as usize;
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            // `lines()` yields subslices of `content`; the pointer delta is the
            // line's byte offset, which indexes the per-byte comment mask.
            let start = line.as_ptr() as usize - base;
            line.bytes()
                .enumerate()
                .any(|(i, b)| !b.is_ascii_whitespace() && !comment[start + i])
        })
        .map(|(idx, line)| (line_number(idx), line))
        .collect()
}

pub fn find_match_in_lines(lines: &[(u32, &str)], pattern: &Regex) -> Option<u32> {
    lines
        .iter()
        .find(|(_, line)| pattern.is_match(line))
        .map(|(line_num, _)| *line_num)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    // `Ord` derives from declaration order: weakest first so `Critical` is the max.
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Maps external linter severity strings to `Severity`. Caps at `High`;
    /// `Critical` is reserved for in-house high-certainty patterns.
    pub fn from_linter_str(s: &str) -> Self {
        match s {
            "error" => Severity::High,
            "warning" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        write!(f, "{s}")
    }
}

/// Marks a violation the hook verified pre-existed the edit by comparing
/// against before content. Attached only to demoted violations while the
/// diff-aware toggle is on; None elsewhere keeps the field out of the JSON
/// wire format, so toggle-off output is unchanged. The hook makes no positive
/// claim that a survivor was introduced: non-allowlisted rules are never
/// before-compared, so an "introduced" mark could not be verified.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationOrigin {
    Preexisting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub fix: String,
    pub file: String,
    pub line: Option<u32>,
    // `Deserialize` decodes child-subprocess violations (#314 parse-in-child).
    // `skip_serializing_if` keeps `origin` off the wire when None, so a decoder
    // must tolerate its absence: `default` supplies None instead of failing with
    // "missing field origin", which would silently drop every structural rule
    // the child found (fail-open). The two attributes are a matched pair.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin: Option<ViolationOrigin>,
}

type Checker = Box<dyn Fn(&str, &str, &[(u32, &str)]) -> Vec<Violation> + Send + Sync>;

pub struct Rule {
    pub file_pattern: Regex,
    checker: Checker,
}

impl Rule {
    pub fn check(&self, content: &str, file_path: &str, lines: &[(u32, &str)]) -> Vec<Violation> {
        (self.checker)(content, file_path, lines)
    }
}

macro_rules! register_rules {
    ($config:expr, $rules:expr, $( $field:ident => $module:ident ),* $(,)?) => {
        $(if $config.rules.$field { $rules.push(&*$module::RULE); })*
    };
}

pub fn load_rules(config: &Config) -> Vec<&'static Rule> {
    let mut rules = Vec::new();
    register_rules!(config, rules,
        sensitive_file    => sensitive_file,
        architecture      => architecture,
        naming            => naming,
        transaction       => transaction,
        security          => security,
        crypto_weak       => crypto_weak,
        generated_file    => generated_file,
        test_location     => test_location,
        dom_access        => dom_access,
        sync_io           => sync_io,
        bundle_size       => bundle_size,
        flaky_test        => flaky_test,
        sensitive_logging => sensitive_logging,
        hardcoded_secrets => hardcoded_secrets,
        http_resource     => http_resource,
        raw_html          => raw_html,
        cot_leakage_marker => cot_leakage_marker,
        service_worker    => service_worker,
        jwt_client        => jwt_client,
    );
    rules
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
pub(in crate::rules) use test_support::{
    assert_under_10ms, check_rule, test_check_program, test_check_program_fail_open,
    REGISTERED_RULE_IDS, UNREGISTERED_RULE_IDS,
};
#[cfg(test)]
pub(crate) use test_support::{ast_fail_open_check, ast_test_check};

#[cfg(test)]
mod doc_catalog;
#[cfg(test)]
mod tests;
