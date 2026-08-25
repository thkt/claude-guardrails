use super::super::{check, check_js};
use crate::rules::{rule_id, Severity};

// T-001: env_var_fallback_nullish_coalescing_jwt_secret_blocked
#[test]
fn env_var_fallback_nullish_coalescing_jwt_secret_blocked() {
    let v = check_js(r#"const s = process.env.JWT_SECRET ?? "fallback";"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
    assert_eq!(v[0].severity, Severity::High);
}

// T-002: env_var_fallback_short_circuit_or_api_key_blocked
#[test]
fn env_var_fallback_short_circuit_or_api_key_blocked() {
    let v = check_js(r#"const k = process.env.API_KEY || "default";"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
}

// T-003: env_var_fallback_sensitive_keywords_all_blocked
#[test]
fn env_var_fallback_sensitive_keywords_all_blocked() {
    for code in [
        r#"const a = process.env.SECRET ?? "x";"#,
        r#"const b = process.env.AUTH_TOKEN ?? "x";"#,
        r#"const c = process.env.USER_PASSWORD ?? "x";"#,
        r#"const d = process.env.API_KEY ?? "x";"#,
        r#"const e = process.env.JWT ?? "x";"#,
        r#"const f = process.env.AWS_CREDENTIAL ?? "x";"#,
        r#"const g = process.env.SECRET_KEY ?? "x";"#,
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 1, "failed for: {code}");
        assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK, "failed for: {code}");
    }
}

// T-004: env_var_fallback_log_level_allowed
#[test]
fn env_var_fallback_log_level_allowed() {
    let v = check_js(r#"const l = process.env.LOG_LEVEL ?? "info";"#);
    assert_eq!(v.len(), 0);
}

// T-005: env_var_fallback_public_and_sort_keys_allowed
#[test]
fn env_var_fallback_public_and_sort_keys_allowed() {
    for code in [
        r#"const k = process.env.PUBLIC_KEY ?? "";"#,
        r#"const s = process.env.SORT_KEY || "asc";"#,
    ] {
        let v = check_js(code);
        assert_eq!(v.len(), 0, "failed for: {code}");
    }
}

// T-024: env_var_fallback_next_public_allowed
// NEXT_PUBLIC_* env vars are exposed to the browser by Next.js, so they are
// public by definition; a hardcoded fallback for one is not a leaked secret
// even though the name carries an API_KEY substring.
#[test]
fn env_var_fallback_next_public_allowed() {
    let v = check_js(r#"const k = process.env.NEXT_PUBLIC_STRIPE_API_KEY || "pk_test_default";"#);
    assert_eq!(v.len(), 0, "NEXT_PUBLIC_ fallback is public, not a secret");
}

// T-006: env_var_fallback_multiline_logical_expression_blocked
#[test]
fn env_var_fallback_multiline_logical_expression_blocked() {
    let v = check_js("const s = process.env.JWT_SECRET\n  ?? \"fallback\";");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
}

// T-019: env_var_fallback_multistage_chain_sensitive_first_blocked
// #295: `a || b || "lit"` は左結合で `(a||b) || "lit"`。最外 left が
// LogicalExpression のため従来は検出漏れ (FN)。sensitive が先頭オペランド。
#[test]
fn env_var_fallback_multistage_chain_sensitive_first_blocked() {
    let v = check_js(r#"const k = process.env.SECRET || process.env.ALT || "x";"#);
    assert_eq!(v.len(), 1, "multi-stage chain must fire exactly once");
    assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
    assert_eq!(v[0].severity, Severity::High);
}

// T-020: env_var_fallback_multistage_chain_sensitive_in_middle_blocked
// #295: sensitive な env access がチェーンの中間オペランドにあるケース。
#[test]
fn env_var_fallback_multistage_chain_sensitive_in_middle_blocked() {
    let v = check_js(r#"const k = process.env.PUB || process.env.JWT_SECRET || "x";"#);
    assert_eq!(v.len(), 1, "sensitive in middle operand must be detected");
    assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
}

// T-021: env_var_fallback_multistage_chain_all_non_sensitive_allowed
// #295 FP 回帰ガード: 多段チェーンでも全 env が non-sensitive なら不発火。
#[test]
fn env_var_fallback_multistage_chain_all_non_sensitive_allowed() {
    let v = check_js(r#"const k = process.env.SORT_KEY || process.env.PUBLIC_KEY || "asc";"#);
    assert_eq!(v.len(), 0, "all-non-sensitive chain must not fire");
}

// T-022: env_var_fallback_multistage_coalesce_chain_blocked
// #295: `??` でも多段チェーンを検出する (Coalesce 再帰経路のカバレッジ)。
#[test]
fn env_var_fallback_multistage_coalesce_chain_blocked() {
    let v = check_js(r#"const k = process.env.PUB ?? process.env.JWT_SECRET ?? "x";"#);
    assert_eq!(v.len(), 1, "?? multi-stage chain must fire exactly once");
    assert_eq!(v[0].rule, rule_id::ENV_VAR_FALLBACK);
}

// T-023: env_var_fallback_literal_mid_chain_fires_per_node
// #295: `env || "x" || "y"` は両ノードとも right が literal のため各ノードで発火
// する。ssr_env.rs の intentional コメント (literal mid-chain は node 毎に独立した
// true positive) を pin し、将来の firing model 変更を検知する。
#[test]
fn env_var_fallback_literal_mid_chain_fires_per_node() {
    let v = check_js(r#"const k = process.env.SECRET || "x" || "y";"#);
    assert_eq!(v.len(), 2, "literal mid-chain fires once per node");
    assert!(v.iter().all(|x| x.rule == rule_id::ENV_VAR_FALLBACK));
}

// T-016: env_var_fallback_fail_open_on_invalid_syntax
#[test]
fn env_var_fallback_fail_open_on_invalid_syntax() {
    let v = check_js("function { invalid !!!");
    assert_eq!(v.len(), 0);
}

#[test]
fn client_env_leak_fires_with_use_client_directive() {
    let code = "\"use client\";\nconst key = process.env.SECRET_API_KEY;";
    let v = check(code, "/src/components/Profile.tsx");
    let leaks: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
        .collect();
    assert_eq!(leaks.len(), 1, "client env leak must flag: {v:?}");
    assert_eq!(leaks[0].severity, Severity::High);
}

#[test]
fn client_env_leak_silent_on_next_public_prefix() {
    let code = "\"use client\";\nconst url = process.env.NEXT_PUBLIC_API_URL;";
    let v = check(code, "/src/components/Profile.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "NEXT_PUBLIC_ prefix is allowed: {v:?}"
    );
}

#[test]
fn client_env_leak_silent_without_directive() {
    let code = "const key = process.env.SECRET_API_KEY;";
    let v = check(code, "/src/lib/util.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "no use client directive: {v:?}"
    );
}

#[test]
fn client_env_leak_silent_in_api_route_even_with_use_client() {
    let code = "\"use client\";\nconst key = process.env.SECRET_API_KEY;";
    let v = check(code, "/src/app/api/users/route.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "API route never executes in browser: {v:?}"
    );
}

#[test]
fn client_env_leak_fires_in_function_call_argument() {
    let code = "\"use client\";\nlogger.debug(process.env.JWT_SECRET);";
    let v = check(code, "/src/components/Profile.tsx");
    let leaks: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
        .collect();
    assert_eq!(
        leaks.len(),
        1,
        "process.env access nested in call still leaks: {v:?}"
    );
}

#[test]
fn client_env_leak_fires_with_single_quote_directive() {
    let code = "'use client';\nconst key = process.env.SECRET_API_KEY;";
    let v = check(code, "/src/components/Profile.tsx");
    let leaks: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
        .collect();
    assert_eq!(leaks.len(), 1, "single-quoted directive must work: {v:?}");
}

#[test]
fn client_env_leak_silent_with_use_server_directive() {
    let code = "\"use server\";\nconst key = process.env.SECRET_API_KEY;";
    let v = check(code, "/src/components/Form.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "use server is server-side: {v:?}"
    );
}

#[test]
fn client_env_leak_fires_for_every_violation_in_file() {
    let code = "\"use client\";\nconst a = process.env.SECRET_API_KEY;\nconst b = process.env.DATABASE_URL;";
    let v = check(code, "/src/components/Profile.tsx");
    let leaks: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::CLIENT_ENV_PUBLIC_LEAK)
        .collect();
    assert_eq!(leaks.len(), 2, "every violation must be reported: {v:?}");
}

#[test]
fn client_env_leak_silent_on_computed_access() {
    let code = "\"use client\";\nconst key = process.env[\"SECRET_API_KEY\"];";
    let v = check(code, "/src/components/Profile.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "computed access is out of scope per draft: {v:?}"
    );
}

#[test]
fn client_env_leak_silent_on_node_env() {
    let code = "\"use client\";\nif (process.env.NODE_ENV === 'production') {}";
    let v = check(code, "/src/components/Profile.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "NODE_ENV is a framework-provided public compile-time value: {v:?}"
    );
}

#[test]
fn client_env_leak_silent_inside_inline_use_server_in_client_component() {
    let code = r#"
        "use client";
        async function submit() {
            "use server";
            const key = process.env.SECRET_API_KEY;
        }
    "#;
    let v = check(code, "/src/components/Profile.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::CLIENT_ENV_PUBLIC_LEAK),
        "inline 'use server' body runs server-side, not in client bundle: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_fires_on_apikey_prop_in_get_server_side_props() {
    let code = "export async function getServerSideProps() { return { props: { apiKey: 'x' } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(bleeds.len(), 1, "apiKey property in props must flag: {v:?}");
    assert_eq!(bleeds[0].severity, Severity::High);
}

#[test]
fn ssr_secret_bleed_fires_on_env_secret_value_in_props() {
    let code = "export async function getServerSideProps() { return { props: { x: process.env.DATABASE_TOKEN } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(
        bleeds.len(),
        1,
        "secret env value in props must flag: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_fires_in_use_server_action_return() {
    let code = "'use server';\nexport async function fetchData() { return { password: 'p', user: { name: 'x' } }; }";
    let v = check(code, "/src/app/actions.ts");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(
        bleeds.len(),
        1,
        "'use server' return with password property must flag: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_fires_on_arrow_get_server_side_props() {
    let code =
        "export const getServerSideProps = async () => { return { props: { token: 't' } }; };";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(bleeds.len(), 1, "arrow form must flag: {v:?}");
}

#[test]
fn ssr_secret_bleed_fires_on_uppercase_property_name() {
    let code = "export async function getServerSideProps() { return { props: { API_KEY: 'x' } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(bleeds.len(), 1, "case-insensitive substring match: {v:?}");
}

#[test]
fn ssr_secret_bleed_fires_on_multiple_violations_in_same_return() {
    let code = "export async function getServerSideProps() { return { props: { apiKey: 'a', dbToken: process.env.DATABASE_TOKEN } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(
        bleeds.len(),
        2,
        "every violating property must be reported: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_outside_ssr_scope() {
    let code = "function helper() { return { token: 'x' }; }";
    let v = check(code, "/src/lib/util.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "helper function with no SSR context is silent: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_safe_property_names() {
    let code = "export async function getServerSideProps() { return { props: { username: 'alice', itemCount: 3 } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "non-secret property names are silent: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_next_public_env_value() {
    // A NEXT_PUBLIC_* value is browser-exposed by Next.js, so returning it from
    // SSR is not a secret bleed even though the name carries an API_KEY substring.
    // Shares the NEXT_PUBLIC_ carve-out with env-var-fallback (is_sensitive_env_access).
    let code = "export async function getServerSideProps() { return { props: { publishableKey: process.env.NEXT_PUBLIC_API_KEY } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "NEXT_PUBLIC_ value is public, not an SSR secret bleed: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_variable_referenced_return() {
    let code = "export async function getServerSideProps() { const data = { props: { apiKey: 'x' } }; return data; }";
    let v = check(code, "/pages/dashboard.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "variable-bound return is out of scope: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_spread_property() {
    let code =
        "export async function getServerSideProps() { return { props: { ...secretData } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "spread element is out of scope (separate issue): {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_in_named_function_other_than_gssp() {
    let code = "export async function getStaticProps() { return { props: { apiKey: 'x' } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "getStaticProps is not in scope for this rule: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_safe_use_server_return() {
    let code =
        "'use server';\nexport async function loadUser() { return { name: 'alice', age: 30 }; }";
    let v = check(code, "/src/app/actions.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "'use server' return with safe properties is silent: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_helper_function_inside_gssp() {
    let code = "export async function getServerSideProps() {\n  function buildHeaders() { return { token: 'h' }; }\n  return { props: { name: 'alice' } };\n}";
    let v = check(code, "/pages/dashboard.tsx");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "helper function return is not serialized: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_helper_function_inside_use_server_file() {
    let code = "'use server';\nexport async function loadUser() {\n  function inner() { return { password: 'p' }; }\n  return { name: 'alice' };\n}";
    let v = check(code, "/src/app/actions.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "inner helper return is not serialized: {v:?}"
    );
}

// Concise arrow body `() => ({ ... })` has no ReturnStatement, so the check
// must run from `visit_arrow_function_expression` instead.
#[test]
fn ssr_secret_bleed_fires_on_concise_arrow_get_server_side_props() {
    let code = "export const getServerSideProps = async () => ({ props: { apiKey: 'x' } });";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(bleeds.len(), 1, "concise arrow body must flag: {v:?}");
}

#[test]
fn ssr_secret_bleed_fires_on_nested_object_in_props() {
    let code = "export async function getServerSideProps() { return { props: { user: { token: process.env.JWT_SECRET } } }; }";
    let v = check(code, "/pages/dashboard.tsx");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(bleeds.len(), 1, "deeply nested secret must flag: {v:?}");
}

#[test]
fn ssr_secret_bleed_fires_on_arrow_use_server_action() {
    let code = "'use server';\nexport const fetchUserSecrets = async (id) => { return { id, apiKey: process.env.STRIPE_SECRET_KEY }; };";
    let v = check(code, "/src/app/actions.ts");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(
        bleeds.len(),
        1,
        "arrow-form 'use server' action with secret env value must flag: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_fires_on_concise_arrow_use_server_action() {
    let code =
        "'use server';\nexport const loadConfig = async () => ({ apiKey: process.env.STRIPE_SECRET_KEY });";
    let v = check(code, "/src/app/actions.ts");
    let bleeds: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::SSR_SECRET_BLEED)
        .collect();
    assert_eq!(
        bleeds.len(),
        1,
        "concise-body arrow 'use server' action must flag: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_safe_arrow_use_server_action() {
    let code =
        "'use server';\nexport const loadUser = async (id) => { return { id, name: 'alice' }; };";
    let v = check(code, "/src/app/actions.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "arrow-form 'use server' action with safe properties is silent: {v:?}"
    );
}

#[test]
fn ssr_secret_bleed_silent_on_helper_arrow_inside_use_server_arrow() {
    let code = "'use server';\nexport const loadUser = async () => {\n  const inner = () => ({ password: 'p' });\n  return { name: 'alice' };\n};";
    let v = check(code, "/src/app/actions.ts");
    assert!(
        v.iter().all(|x| x.rule != rule_id::SSR_SECRET_BLEED),
        "inner helper arrow return is not serialized to client: {v:?}"
    );
}

/// Returns the sole `rule` violation's fix message. Asserting the fire here
/// keeps a rule deletion from making the opacity checks below vacuously pass.
fn sole_fix_message(code: &str, path: &str, rule: &str) -> String {
    let v = check(code, path);
    let hits: Vec<_> = v.iter().filter(|x| x.rule == rule).collect();
    assert_eq!(hits.len(), 1, "{rule} must flag once: {v:?}");
    hits[0].fix.clone()
}

// T-616: client_env_leak_fix_message_omits_public_prefix_token
// Not a detection test: the message is what the agent acts on (ADR-0022, #473).
#[test]
fn client_env_leak_fix_message_omits_public_prefix_token() {
    let fix = sole_fix_message(
        "\"use client\";\nconst k = process.env.API_SECRET;",
        "/src/components/Profile.tsx",
        rule_id::CLIENT_ENV_PUBLIC_LEAK,
    );
    let lower = fix.to_ascii_lowercase();
    // Not just the prefix: CLIENT_ENV_ALLOW_LIST's NODE_ENV is the second lever.
    for token in ["next_public", "next public", "node_env"] {
        assert!(
            !lower.contains(token),
            "fix message names {token}, which silences the rule: {fix}"
        );
    }
}

// T-617: ssr_secret_bleed_fix_message_omits_rename_instruction
// Not a detection test: a rename silences the match while the secret still
// ships to the client (ADR-0022, #473).
#[test]
fn ssr_secret_bleed_fix_message_omits_rename_instruction() {
    let fix = sole_fix_message(
        "export async function getServerSideProps() { return { props: { apiKey: 'x' } }; }",
        "/pages/dashboard.tsx",
        rule_id::SSR_SECRET_BLEED,
    );
    assert!(
        !fix.to_ascii_lowercase().contains("rename"),
        "fix message offers a rename, which silences the name-only match: {fix}"
    );
}
