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
mod test_assertion;
mod test_location;
mod transaction;

use crate::config::Config;
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
    }
}

/// `security` module だけ 2 `rule_id` (SECURITY / `DANGEROUS_INNER_HTML`) emit する。
#[cfg(test)]
const REGISTERED_RULE_IDS: &[&str] = &[
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
    rule_id::TEST_ASSERTION,
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
#[cfg(test)]
const UNREGISTERED_RULE_IDS: &[&str] = &[
    rule_id::BIDI_CHARACTERS,            // ast_security::check_bidi
    rule_id::CHILD_PROCESS_INJECTION,    // ast_security::check_child_process
    rule_id::CLIENT_ENV_PUBLIC_LEAK,     // ast_security::check_client_env_public_leak
    rule_id::ENV_VAR_FALLBACK,           // ast_security::check_env_var_fallback
    rule_id::ERR_STACK_EXPOSURE,         // ast_security::check_err_stack
    rule_id::MATH_RANDOM_INSECURE,       // ast_security::check_math_random_*
    rule_id::NON_LITERAL_FS_PATH,        // ast_security::check_fs_path
    rule_id::NON_LITERAL_REQUIRE,        // ast_security::check_non_literal_require
    rule_id::POSTMESSAGE_ORIGIN_MISSING, // ast_security::check_{postmessage,onmessage}_origin_missing
    rule_id::PROTOTYPE_POLLUTION, // ast_security::check_{prototype_pollution,merge_pollution_sinks}
    rule_id::SSR_SECRET_BLEED,    // ast_security::check_ssr_secret_*
    rule_id::UNSAFE_HTML_INJECTION, // ast_security::check_{html_assignment,document_write}
    rule_id::UNSAFE_REGEX,        // ast_security::check_unsafe_regex
    rule_id::CORS_WILDCARD,       // main.rs から cors_wildcard::check_program を直接呼ぶ
    rule_id::EVAL,                // ADR-0009 oxlint 委譲、Rust 側は eval::check_program
    rule_id::NO_USE_EFFECT,       // main.rs から no_use_effect::check_program を直接呼ぶ
    rule_id::OPEN_REDIRECT,       // main.rs から open_redirect::check_program を直接呼ぶ
    rule_id::SQLI_CONCAT,         // main.rs から sqli_concat::check_program を直接呼ぶ
];

pub static RE_JS_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(tsx?|jsx?)$").expect("RE_JS_FILE: invalid regex"));

pub static RE_TEST_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(test|spec)\.[jt]sx?$").expect("RE_TEST_FILE: invalid regex"));

pub static RE_ALL_FILES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r".").expect("RE_ALL_FILES: invalid regex"));

pub static RE_REACT_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(tsx|jsx)$").expect("RE_REACT_FILE: invalid regex"));

pub const API_PREFIX_PAT: &str = r"(^|/)(app|pages)/api/";

pub static RE_API_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(API_PREFIX_PAT).expect("RE_API_FILE: invalid regex"));

pub static RE_API_OR_MIDDLEWARE_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("{API_PREFIX_PAT}|(^|/)middleware\\.[jt]sx?$"))
        .expect("RE_API_OR_MIDDLEWARE_FILE: invalid regex")
});

pub static RE_API_OR_ROUTE_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("{API_PREFIX_PAT}|(^|/)app/(.*/)?route\\.[jt]sx?$"))
        .expect("RE_API_OR_ROUTE_FILE: invalid regex")
});

/// Matches `* ` (with space) or bare `*` to avoid `x * y` false positives.
fn is_line_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("* ") || trimmed == "*"
}

/// Known limitation: `/*`/`*/` inside string literals are treated as comment markers.
pub(crate) fn non_comment_lines(content: &str) -> Vec<(u32, &str)> {
    let mut result = Vec::new();
    let mut in_block = false;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if in_block {
            if let Some(pos) = trimmed.find("*/") {
                in_block = false;
                let after = trimmed[pos + 2..].trim();
                if !after.is_empty() && !is_line_comment(after) {
                    result.push((u32::try_from(idx + 1).unwrap_or(u32::MAX), line));
                }
            }
            continue;
        }
        if let Some(pos) = trimmed.find("/*") {
            let before = trimmed[..pos].trim();
            if !trimmed[pos..].contains("*/") {
                in_block = true;
                if !before.is_empty() {
                    result.push((u32::try_from(idx + 1).unwrap_or(u32::MAX), line));
                }
                continue;
            }
            // Inline block comment like `code /* comment */ code`
            if before.is_empty() && trimmed[pos..].ends_with("*/") {
                continue;
            }
        }
        if is_line_comment(line) {
            continue;
        }
        result.push((u32::try_from(idx + 1).unwrap_or(u32::MAX), line));
    }
    result
}

pub fn find_match_in_lines(lines: &[(u32, &str)], pattern: &Regex) -> Option<u32> {
    lines
        .iter()
        .find(|(_, line)| pattern.is_match(line))
        .map(|(line_num, _)| *line_num)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
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

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub fix: String,
    pub file: String,
    pub line: Option<u32>,
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
        $(if $config.rules.$field { $rules.push($module::rule()); })*
    };
}

pub fn load_rules(config: &Config) -> Vec<Rule> {
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
        test_assertion    => test_assertion,
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
mod tests {
    use super::*;

    #[test]
    fn single_line_comments_filtered() {
        let content = "code\n// comment\nmore code";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (3, "more code")]);
    }

    #[test]
    fn jsdoc_star_lines_filtered() {
        let content = "code\n * jsdoc line\n *\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (4, "more")]);
    }

    #[test]
    fn block_comment_single_line() {
        let content = "code\n/* inline comment */\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (3, "more")]);
    }

    #[test]
    fn block_comment_body_without_star_prefix() {
        // Body lines without `* ` prefix must still be filtered inside block comments
        let content =
            "let x = 1;\n/*\nThis line has no star prefix\nNeither does this one\n*/\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1;"), (6, "let y = 2;")]);
    }

    #[test]
    fn block_comment_with_code_before_open() {
        let content = "let x = 1; /*\ncomment body\n*/\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1; /*"), (4, "let y = 2;")]);
    }

    #[test]
    fn block_comment_with_code_after_close() {
        let content = "/*\ncomment\n*/ let x = 1;\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(3, "*/ let x = 1;"), (4, "let y = 2;")]);
    }

    #[test]
    fn nested_style_block_comments() {
        // Nested block comments are not supported; matches first */
        let content = "code\n/* outer\n/* inner */\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (4, "more")]);
    }

    #[test]
    fn empty_content() {
        let lines: Vec<_> = non_comment_lines("");
        assert!(lines.is_empty());
    }

    #[test]
    fn no_comments() {
        let content = "let x = 1;\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1;"), (2, "let y = 2;")]);
    }

    #[test]
    fn find_match_in_lines_skips_block_comments() {
        let re = Regex::new(r"TODO").unwrap();
        let content = "/*\nTODO: fix this\n*/\nlet x = 1;";
        assert_eq!(find_match_in_lines(&non_comment_lines(content), &re), None);
    }

    #[test]
    fn severity_from_linter_str() {
        assert_eq!(Severity::from_linter_str("error"), Severity::High);
        assert_eq!(Severity::from_linter_str("warning"), Severity::Medium);
        assert_eq!(Severity::from_linter_str("info"), Severity::Low);
        assert_eq!(Severity::from_linter_str("unknown"), Severity::Low);
    }

    #[test]
    fn re_api_file_matches_app_api_and_pages_api() {
        assert!(RE_API_FILE.is_match("/src/app/api/users/route.ts"));
        assert!(RE_API_FILE.is_match("/src/pages/api/users.ts"));
        assert!(RE_API_FILE.is_match("app/api/route.ts"));
    }

    #[test]
    fn re_api_file_rejects_near_miss_paths() {
        assert!(!RE_API_FILE.is_match("/src/myapp/api/users.ts"));
        assert!(!RE_API_FILE.is_match("/src/components/api.ts"));
        assert!(!RE_API_FILE.is_match("/src/pages/users.ts"));
        assert!(!RE_API_FILE.is_match("/src/api/users.ts"));
    }

    #[test]
    fn re_api_or_middleware_matches_middleware_files() {
        assert!(RE_API_OR_MIDDLEWARE_FILE.is_match("/middleware.ts"));
        assert!(RE_API_OR_MIDDLEWARE_FILE.is_match("/src/middleware.js"));
        assert!(RE_API_OR_MIDDLEWARE_FILE.is_match("/src/app/api/route.ts"));
    }

    #[test]
    fn re_api_or_middleware_rejects_near_miss_paths() {
        assert!(!RE_API_OR_MIDDLEWARE_FILE.is_match("/src/mymiddleware.ts"));
        assert!(!RE_API_OR_MIDDLEWARE_FILE.is_match("/src/middlewares/auth.ts"));
        assert!(!RE_API_OR_MIDDLEWARE_FILE.is_match("/src/middleware/index.ts"));
    }

    #[test]
    fn re_api_or_route_matches_app_route_segments() {
        assert!(RE_API_OR_ROUTE_FILE.is_match("/src/app/orders/route.ts"));
        assert!(RE_API_OR_ROUTE_FILE.is_match("/src/app/[id]/route.tsx"));
        assert!(RE_API_OR_ROUTE_FILE.is_match("/src/app/api/users/route.ts"));
        assert!(RE_API_OR_ROUTE_FILE.is_match("/src/app/route.ts"));
    }

    #[test]
    fn re_api_or_route_rejects_near_miss_paths() {
        assert!(!RE_API_OR_ROUTE_FILE.is_match("/src/lib/route.ts"));
        assert!(!RE_API_OR_ROUTE_FILE.is_match("/src/myapp/api/users.ts"));
        assert!(!RE_API_OR_ROUTE_FILE.is_match("/src/app/route-helper.ts"));
    }

    // --- Known limitations ---

    #[test]
    fn known_limitation_block_comment_in_string_literal() {
        let content = "let x = '/* not a comment */';\nreal code;";
        let lines: Vec<_> = non_comment_lines(content);
        // `/*` inside string opens block comment; `*/` closes it on same line.
        assert_eq!(
            lines,
            vec![(1, "let x = '/* not a comment */';"), (2, "real code;")]
        );
    }

    #[test]
    fn known_limitation_block_comment_in_string_spans_lines() {
        let content = "let x = '/*';\nreal code;\nlet y = '*/';\nmore code;";
        let lines: Vec<_> = non_comment_lines(content);
        // `/*` in string opens block; lines 2-3 treated as inside block comment.
        assert_eq!(
            lines,
            vec![
                (1, "let x = '/*';"),
                (3, "let y = '*/';"),
                (4, "more code;")
            ]
        );
    }

    #[test]
    fn inline_block_comment_with_code_on_both_sides() {
        let content = "let x = 1; /* inline */ let y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        // Code exists on both sides of inline block comment — line should be included.
        assert_eq!(lines, vec![(1, "let x = 1; /* inline */ let y = 2;")]);
    }

    // --- load_rules ---

    #[test]
    fn load_rules_default_config_loads_all() {
        let config = Config::default();
        let rules = load_rules(&config);
        assert_eq!(rules.len(), 20);
    }

    #[test]
    fn load_rules_respects_disabled_rule() {
        let all_count = load_rules(&Config::default()).len();
        let mut config = Config::default();
        config.rules.security = false;
        config.rules.crypto_weak = false;
        let rules = load_rules(&config);
        assert_eq!(rules.len(), all_count - 2);
    }

    // --- rule_id catalog ---

    #[test]
    fn rule_id_catalog_entries_match_allowlists() {
        use std::collections::HashSet;
        let declared: HashSet<&str> = rule_id::RULE_ID_CATALOG.iter().copied().collect();
        let registered: HashSet<&str> = REGISTERED_RULE_IDS.iter().copied().collect();
        let unregistered: HashSet<&str> = UNREGISTERED_RULE_IDS.iter().copied().collect();

        let covered: HashSet<&str> = registered.union(&unregistered).copied().collect();
        let orphaned: Vec<&&str> = declared.difference(&covered).collect();
        assert!(
            orphaned.is_empty(),
            "rule_id 定数が REGISTERED_RULE_IDS にも UNREGISTERED_RULE_IDS にも含まれていない: {orphaned:?}"
        );

        let extra: Vec<&&str> = covered.difference(&declared).collect();
        assert!(
            extra.is_empty(),
            "REGISTERED/UNREGISTERED に rule_id::RULE_ID_CATALOG にない entry: {extra:?}"
        );
    }

    #[test]
    fn rule_id_catalog_registered_and_unregistered_are_disjoint() {
        use std::collections::HashSet;
        let registered: HashSet<&str> = REGISTERED_RULE_IDS.iter().copied().collect();
        let unregistered: HashSet<&str> = UNREGISTERED_RULE_IDS.iter().copied().collect();
        let overlap: Vec<&&str> = registered.intersection(&unregistered).collect();
        assert!(
            overlap.is_empty(),
            "rule_id が REGISTERED と UNREGISTERED の両方に登録されている: {overlap:?}"
        );
    }
}
