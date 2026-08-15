use super::*;

#[test]
fn single_line_comments_filtered() {
    let content = "code\n// comment\nmore code";
    let lines: Vec<_> = non_comment_lines(content);
    assert_eq!(lines, vec![(1, "code"), (3, "more code")]);
}

#[test]
fn jsdoc_star_lines_outside_block_are_code() {
    // Drift pin: `* `/`*` lines are only comments when a real `/* */` block
    // encloses them. With no enclosing block, `build_source_masks` marks none
    // as comment, so they survive as code (previously dropped by the hand-rolled
    // `is_line_comment` heuristic).
    let content = "code\n * jsdoc line\n *\nmore";
    let lines: Vec<_> = non_comment_lines(content);
    assert_eq!(
        lines,
        vec![(1, "code"), (2, " * jsdoc line"), (3, " *"), (4, "more")]
    );
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
fn blank_and_whitespace_only_lines_omitted() {
    // Pin: a line with no visible (non-whitespace) byte is dropped. Callers key
    // on returned line text, so the index gaps are inert (no FN/FP).
    let content = "code\n\n   \nmore";
    let lines: Vec<_> = non_comment_lines(content);
    assert_eq!(lines, vec![(1, "code"), (4, "more")]);
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
fn severity_orders_low_to_critical() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    let max = [Severity::Low, Severity::Critical, Severity::Medium]
        .into_iter()
        .max();
    assert_eq!(max, Some(Severity::Critical));
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

#[test]
fn re_js_file_matches_esm_and_classic_extensions() {
    for ext in [
        "foo.js", "foo.ts", "foo.jsx", "foo.tsx", "foo.mjs", "foo.mts",
    ] {
        assert!(RE_JS_FILE.is_match(ext), "{ext} should be JS-analyzed");
    }
}

#[test]
fn re_js_file_rejects_commonjs_extensions() {
    // .cjs/.cts are Node tooling (build config, CLI), out of OUTCOME scope.
    for ext in ["foo.cjs", "foo.cts", "foo.json", "foo.css"] {
        assert!(!RE_JS_FILE.is_match(ext), "{ext} must not be JS-analyzed");
    }
}

#[test]
fn re_test_file_co_extends_to_esm() {
    // ESM test files keep ast-security's test exemption (is_test_file=true).
    for ext in ["a.test.mjs", "a.test.mts", "a.spec.mjs", "a.test.js"] {
        assert!(RE_TEST_FILE.is_match(ext), "{ext} should classify as test");
    }
}

#[test]
fn re_test_file_rejects_commonjs_test_extensions() {
    for ext in ["a.test.cjs", "a.spec.cts"] {
        assert!(
            !RE_TEST_FILE.is_match(ext),
            "{ext} must not classify as test"
        );
    }
}

#[test]
fn re_react_file_excludes_esm_non_jsx_extensions() {
    // .mjs/.mts are not JSX, so React-only rules stay scoped to .tsx/.jsx.
    for ext in ["foo.mjs", "foo.mts", "foo.js", "foo.ts"] {
        assert!(
            !RE_REACT_FILE.is_match(ext),
            "{ext} must not be React-scoped"
        );
    }
}

// --- String-literal comment markers (not mistaken for comments) ---

#[test]
fn block_comment_markers_in_string_literal_ignored() {
    let content = "let x = '/* not a comment */';\nreal code;";
    let lines: Vec<_> = non_comment_lines(content);
    // `/*`/`*/` sit inside a string literal, so `build_source_masks` keeps the
    // whole line as code; both lines survive.
    assert_eq!(
        lines,
        vec![(1, "let x = '/* not a comment */';"), (2, "real code;")]
    );
}

#[test]
fn block_comment_markers_in_string_across_lines_ignored() {
    let content = "let x = '/*';\nreal code;\nlet y = '*/';\nmore code;";
    let lines: Vec<_> = non_comment_lines(content);
    // `/*` is string content, not a block-comment open, so line 2 stays code.
    // The pre-fix hand-rolled parser dropped `real code;` here (the bug #301 fixes).
    assert_eq!(
        lines,
        vec![
            (1, "let x = '/*';"),
            (2, "real code;"),
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
    // test-assertion runs on the AST path (run_ast_rules), not register_rules!.
    assert_eq!(rules.len(), 19);
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

// `oxlint` は固定の rule_id 集合を持たないので `toggle_rule_id_count` は
// None を返す。

// T-527: oxlint は数を持たない値を返す
#[test]
fn oxlint_は数を持たない値を返す() {
    assert_eq!(toggle_rule_id_count("oxlint"), None);
}

// U-001: toggle_rule_id_count が、他の toggle からも出る rule_id を数から引く。
// "security" rule_id は "security" toggle の一覧に載るが、
// `analysis::ast_security::postmessage::check_post_message_wildcard` も同じ
// rule_id を独立に発火するので、"security" toggle を切っても止まらない
// (複数 emitter を持つ rule)。

// T-550: security は1を返す
#[test]
fn security_は1を返す() {
    assert_eq!(toggle_rule_id_count("security"), Some(1));
}

// T-551: astSecurity は14を返す
#[test]
fn ast_security_は14を返す() {
    assert_eq!(toggle_rule_id_count("astSecurity"), Some(14));
}

// T-552: rule_id と1対1の toggle は1を返す
#[test]
fn rule_id_と1対1の_toggle_は1を返す() {
    assert_eq!(toggle_rule_id_count("sensitiveFile"), Some(1));
}

#[test]
#[should_panic(expected = "ast_test_check: no AST produced for /broken.ts")]
fn ast_test_check_panics_on_parser_failure() {
    ast_test_check("const x = ;", "/broken.ts", |_, _| Vec::new());
}

#[test]
#[should_panic(expected = "ast_test_check: no AST produced for /docs/README.md")]
fn ast_test_check_panics_on_unsupported_extension() {
    ast_test_check("any content", "/docs/README.md", |_, _| Vec::new());
}
