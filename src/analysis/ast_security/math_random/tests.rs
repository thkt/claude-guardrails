use super::super::{check, check_js};
use crate::rules::{rule_id, Severity};

// T-011: math_random_insecure_to_string_36_blocked
#[test]
fn math_random_insecure_to_string_36_blocked() {
    let v = check_js("const t = Math.random().toString(36).substring(2);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-011: math_random_insecure_to_string_36_no_chain_blocked
#[test]
fn math_random_insecure_to_string_36_no_chain_blocked() {
    let v = check_js("const t = Math.random().toString(36);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
}

// T-012: math_random_insecure_test_file_excluded
#[test]
fn math_random_insecure_test_file_excluded() {
    for path in [
        "/src/util.test.ts",
        "/src/util.spec.tsx",
        "/src/util.test.js",
        "/src/util.test.jsx",
        "/src/util.spec.js",
    ] {
        let v = check("const t = Math.random().toString(36);", path);
        assert_eq!(v.len(), 0, "expected 0 violations for {path}");
    }
}

// T-013: math_random_multiplied_allowed
#[test]
fn math_random_multiplied_allowed() {
    let v = check_js("const x = Math.random() * 100;");
    assert_eq!(v.len(), 0);
}

// T-014: math_random_react_key_allowed
#[test]
fn math_random_react_key_allowed() {
    let v = check("<li key={Math.random()}>x</li>", "/src/List.tsx");
    assert_eq!(v.len(), 0);
}

// T-015: math_random_set_timeout_jitter_allowed
#[test]
fn math_random_set_timeout_jitter_allowed() {
    let v = check_js("setTimeout(fn, 100 + Math.random() * 50);");
    assert_eq!(v.len(), 0);
}

// T-016: math_random_insecure_fail_open_on_invalid_syntax
#[test]
fn math_random_insecure_fail_open_on_invalid_syntax() {
    let v = check_js("function { Math.random().toString(36) !!!");
    assert_eq!(v.len(), 0);
}

// T-022: math_random_crypto_sink_bcrypt_hash_blocked
#[test]
fn math_random_crypto_sink_bcrypt_hash_blocked() {
    let v = check_js(r#"bcrypt.hash("pwd", Math.random());"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-023: math_random_crypto_sink_jwt_sign_blocked
#[test]
fn math_random_crypto_sink_jwt_sign_blocked() {
    let v = check_js("jsonwebtoken.sign(payload, Math.random());");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-024: math_random_crypto_sink_subtle_import_key_blocked
#[test]
fn math_random_crypto_sink_subtle_import_key_blocked() {
    let v = check_js(r#"crypto.subtle.importKey("raw", Math.random(), algo, false, ["sign"]);"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-025: math_random_crypto_sink_create_cipheriv_blocked
#[test]
fn math_random_crypto_sink_create_cipheriv_blocked() {
    let v = check_js(r#"crypto.createCipheriv("aes-256-cbc", Math.random(), iv);"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-025b: math_random_crypto_sink_create_hmac_blocked
#[test]
fn math_random_crypto_sink_create_hmac_blocked() {
    let v = check_js(r#"crypto.createHmac("sha256", Math.random());"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-026: math_random_crypto_sink_bcrypt_with_precomputed_salt_allowed
#[test]
fn math_random_crypto_sink_bcrypt_with_precomputed_salt_allowed() {
    let v = check_js(r#"bcrypt.hash("pwd", precomputedSalt);"#);
    assert_eq!(v.len(), 0);
}

// T-027: math_random_keyword_var_token_blocked
#[test]
fn math_random_keyword_var_token_blocked() {
    let v = check_js("const token = Math.random();");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-028: math_random_keyword_var_math_floor_wrapper_blocked
#[test]
fn math_random_keyword_var_math_floor_wrapper_blocked() {
    let v = check_js("const apiKey = Math.floor(Math.random() * 1000000);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-028b: math_random_keyword_var_division_wrapper_blocked
#[test]
fn math_random_keyword_var_division_wrapper_blocked() {
    let v = check_js("const userId = Math.random() / 1000;");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-029: math_random_keyword_var_multiplication_pass_pattern_allowed
#[test]
fn math_random_keyword_var_multiplication_pass_pattern_allowed() {
    let v = check_js("const token = Math.random() * 100;");
    assert_eq!(v.len(), 0);
}

// T-030: math_random_keyword_fn_declaration_blocked
#[test]
fn math_random_keyword_fn_declaration_blocked() {
    let v = check_js("function generateToken() { return Math.random(); }");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-031: math_random_keyword_fn_arrow_with_parent_blocked
#[test]
fn math_random_keyword_fn_arrow_with_parent_blocked() {
    let v = check_js("const generateSessionId = () => Math.floor(Math.random() * 1000000);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-042: math_random_keyword_var_in_keyword_fn_dedup_to_one
// keyword_var (decl.span) と keyword_fn (call.span) は同一 Math.random() に対し
// 別 span で発火し同一 line に解決する。返却直前の line 単位 dedup で 1 件に集約し、
// より具体的な keyword_var 側 message を残す (#297)。
#[test]
fn math_random_keyword_var_in_keyword_fn_dedup_to_one() {
    let v = check_js("function generateToken() { const token = Math.random(); return token; }");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
    assert!(
        v[0].fix.contains("assigned to a security-named variable"),
        "expected keyword_var message to survive dedup, got: {:?}",
        v[0].fix
    );
}

// T-043: math_random_tostring_in_keyword_fn_keeps_high
// security fn 内の `Math.random().toString(36)` は toString36 (High) と keyword_fn
// (Medium) が同一 line に発火する。dedup は keep-highest-severity で High を残し、
// blocking 違反を Medium に潰さない (#297)。
#[test]
fn math_random_tostring_in_keyword_fn_keeps_high() {
    let v = check_js("const generateToken = () => Math.random().toString(36).substring(2);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-044: math_random_dedup_medium_before_high_keeps_high
// 1 物理行に Medium (keyword_var, 先 push) と High (toString36, 後 push) が並ぶと、
// dedup の置換分岐が走り High を残す。keep-first なら Medium が残るため、
// keep-highest-severity 不変量を keep-first から区別する唯一の assertion (#297)。
#[test]
fn math_random_dedup_medium_before_high_keeps_high() {
    let v = check_js("const token = Math.random(); const key = Math.random().toString(36);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-032: math_random_keyword_fn_no_keyword_match_allowed
#[test]
fn math_random_keyword_fn_no_keyword_match_allowed() {
    let v = check_js("function generateAnimOffset() { return Math.random() * 360; }");
    assert_eq!(v.len(), 0);
}

// T-033: math_random_to_string_no_arg_blocked
#[test]
fn math_random_to_string_no_arg_blocked() {
    let v = check_js("const x = Math.random().toString();");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-034: math_random_to_fixed_blocked
#[test]
fn math_random_to_fixed_blocked() {
    let v = check_js("const x = Math.random().toFixed(8);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::Medium);
}

// T-035: math_random_to_string_36_remains_high
#[test]
fn math_random_to_string_36_remains_high() {
    let v = check_js("const x = Math.random().toString(36);");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, rule_id::MATH_RANDOM_INSECURE);
    assert_eq!(v[0].severity, Severity::High);
}

// T-038: math_random_crypto_sink_parenthesized_blocked
#[test]
fn math_random_crypto_sink_parenthesized_blocked() {
    let v = check_js(r#"bcrypt.hash("pwd", (Math.random()));"#);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].severity, Severity::High);
}

// T-039: math_random_crypto_sink_wrapped_arg_blocked
#[test]
fn math_random_crypto_sink_wrapped_arg_blocked() {
    let v = check_js(r#"bcrypt.hash("pwd", Math.random().toString());"#);
    assert!(
        v.iter().any(|v| v.severity == Severity::High),
        "expected at least one High violation, got: {v:?}"
    );
}

// T-040: math_random_keyword_fn_method_definition_blocked
#[test]
fn math_random_keyword_fn_method_definition_blocked() {
    let v = check_js("class Auth { generateToken() { return Math.random(); } }");
    assert!(
        v.iter().any(|v| v.severity == Severity::Medium),
        "expected at least one Medium violation, got: {v:?}"
    );
}

// T-041: math_random_keyword_fn_object_property_blocked
#[test]
fn math_random_keyword_fn_object_property_blocked() {
    let v = check_js("const auth = { generateToken: () => Math.random() };");
    assert!(
        v.iter().any(|v| v.severity == Severity::Medium),
        "expected at least one Medium violation, got: {v:?}"
    );
}

// T-045: math_random_keyword_var_snake_case_blocked (#304)
// `_` 折り畳み統一前は `api_key` が "apikey" に一致せず検出漏れだった。
#[test]
fn math_random_keyword_var_snake_case_blocked() {
    let v = check_js("const api_key = Math.random();");
    assert!(
        v.iter().any(|v| v.severity == Severity::Medium),
        "expected snake_case api_key to be flagged, got: {v:?}"
    );
}

// T-046: math_random_keyword_var_snake_case_jitter_allowed (#304)
// 折り畳みで `user_identity`→"useridentity"⊃"userid" は一致するが、加算+乗算 jitter は
// rhs_has_insecure_math_random のカーブアウト (T-029) で無発火。
#[test]
fn math_random_keyword_var_snake_case_jitter_allowed() {
    let v = check_js("const user_identity = base + Math.random() * 1000;");
    assert_eq!(
        v.len(),
        0,
        "expected jitter multiplication to be carved out, got: {v:?}"
    );
}

// T-047: math_random_keyword_var_short_word_bridge_fires (#304)
// `is_alt`→"isalt"⊃"salt"。折り畳みが widen した superset 挙動を明示 pin する。
// 直接代入経路では発火する (coincidental-substring FP は許容、word-boundary は対象外)。
#[test]
fn math_random_keyword_var_short_word_bridge_fires() {
    let v = check_js("const is_alt = Math.random();");
    assert!(
        v.iter().any(|v| v.severity == Severity::Medium),
        "expected underscore-bridged salt match to fire, got: {v:?}"
    );
}
