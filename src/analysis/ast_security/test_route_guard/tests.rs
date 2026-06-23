use super::super::check;
use crate::rules::{rule_id, Severity};

const TEST_ROUTE: &str = "/src/app/api/test-setup/route.ts";

fn warns(code: &str, path: &str) -> bool {
    check(code, path)
        .iter()
        .any(|v| v.rule == rule_id::TEST_ENDPOINT_PROD_GUARD)
}

// T-1: test route with no production guard warns (AC1)
#[test]
fn test_route_without_guard_warns() {
    let v = check(
        "export function GET() { return Response.json({ ok: true }); }",
        TEST_ROUTE,
    );
    let hits: Vec<_> = v
        .iter()
        .filter(|v| v.rule == rule_id::TEST_ENDPOINT_PROD_GUARD)
        .collect();
    assert_eq!(hits.len(), 1, "expected exactly one advisory");
    assert_eq!(hits[0].severity, Severity::Medium);
    assert_eq!(hits[0].line, Some(1));
}

// T-2: form A `=== 'production'` early return suppresses the warn (AC2)
#[test]
fn form_a_strict_equality_early_return_passes() {
    let code = "export function GET() { if (process.env.NODE_ENV === 'production') { return new Response('Not found', { status: 404 }); } return Response.json({ ok: true }); }";
    assert!(!warns(code, TEST_ROUTE));
}

// T-3: form B `!== 'production'` inverted guard suppresses the warn (AC3)
#[test]
fn form_b_inverted_guard_passes() {
    let code = "export function GET() { if (process.env.NODE_ENV !== 'production') { return Response.json({ ok: true }); } return new Response(null, { status: 404 }); }";
    assert!(!warns(code, TEST_ROUTE));
}

// T-4: non-test route file with no guard does not warn (AC4)
#[test]
fn non_test_route_does_not_warn() {
    let code = "export function GET() { return Response.json({ ok: true }); }";
    assert!(!warns(code, "/src/app/api/users/route.ts"));
}

// T-5: string-argument router in a non-route file is out of scope (AC5)
#[test]
fn string_argument_router_out_of_scope() {
    let code = "app.get('/api/test', (req, res) => res.json({ ok: true }));";
    assert!(!warns(code, "/src/server.ts"));
}

// T-6: production paths that merely start with a keyword prefix are excluded
#[test]
fn lookalike_production_paths_excluded() {
    let code = "export function GET() { return Response.json({ ok: true }); }";
    for path in [
        "/src/app/api/developers/route.ts",
        "/src/app/api/device-tokens/route.ts",
        "/src/app/api/seedlings/route.ts",
        "/src/app/api/testimonials/route.ts",
    ] {
        assert!(!warns(code, path), "should not warn for {path}");
    }
}

// T-7: pages router where the filename itself is the endpoint warns
#[test]
fn pages_router_filename_endpoint_warns() {
    let code = "export default function handler(req, res) { res.json({ ok: true }); }";
    assert!(warns(code, "/src/pages/api/seed.ts"));
}

// T-8: ternary guard is accepted regardless of statement shape (C3)
#[test]
fn ternary_guard_passes() {
    let code = "export function GET() { return process.env.NODE_ENV === 'production' ? new Response(null, { status: 404 }) : Response.json({ ok: true }); }";
    assert!(!warns(code, TEST_ROUTE));
}

// T-9: variable-bound guard is accepted (C3)
#[test]
fn variable_bound_guard_passes() {
    let code = "const isProd = process.env.NODE_ENV === 'production'; export function GET() { if (isProd) return new Response(null, { status: 404 }); return Response.json({ ok: true }); }";
    assert!(!warns(code, TEST_ROUTE));
}

// T-10: a guard string living only in a comment does not count (AST, not text)
#[test]
fn comment_only_guard_still_warns() {
    let code = "// if (process.env.NODE_ENV === 'production') return notFound();\nexport function GET() { return Response.json({ ok: true }); }";
    assert!(warns(code, TEST_ROUTE));
}

// T-11: comparing NODE_ENV to a non-production value is not a production guard
#[test]
fn non_production_literal_still_warns() {
    let code = "export function GET() { if (process.env.NODE_ENV === 'staging') return new Response(null, { status: 404 }); return Response.json({ ok: true }); }";
    assert!(warns(code, TEST_ROUTE));
}

// T-12: a `.test.ts` unit test file is not a route to guard
#[test]
fn unit_test_file_out_of_scope() {
    let code = "export function GET() { return Response.json({ ok: true }); }";
    assert!(!warns(code, "/src/app/api/foo/route.test.ts"));
}

// T-13: loose-equality guards (`==` / `!=`) are accepted, covering the
// `Equality` / `Inequality` arms of `is_node_env_prod_comparison`
#[test]
fn loose_equality_guards_pass() {
    for op in ["==", "!="] {
        let code = format!(
            "export function GET() {{ if (process.env.NODE_ENV {op} 'production') return new Response(null, {{ status: 404 }}); return Response.json({{ ok: true }}); }}"
        );
        assert!(!warns(&code, TEST_ROUTE), "loose `{op}` guard should pass");
    }
}

// T-14: reversed operand order (`'production' === process.env.NODE_ENV`) is
// accepted, covering the second OR branch of the operand check
#[test]
fn reversed_operand_order_guard_passes() {
    let code = "export function GET() { if ('production' === process.env.NODE_ENV) return new Response(null, { status: 404 }); return Response.json({ ok: true }); }";
    assert!(!warns(code, TEST_ROUTE));
}

// T-15: each test-route keyword (`dev` / `debug` / `fixture`) fires on its own,
// so dropping one from the segment regex is caught
#[test]
fn each_route_keyword_warns() {
    let code = "export function GET() { return Response.json({ ok: true }); }";
    for path in [
        "/src/app/api/dev/route.ts",
        "/src/app/api/debug/route.ts",
        "/src/app/api/fixture/route.ts",
    ] {
        assert!(warns(code, path), "expected warn for {path}");
    }
}

// T-16: a guard in one handler suppresses the warn for the whole file, and the
// file is reported at most once (whole-file presence, single emit)
#[test]
fn guard_in_one_handler_suppresses_file_and_emits_once() {
    let guarded_then_unguarded = "export function GET() { if (process.env.NODE_ENV === 'production') return new Response(null, { status: 404 }); return Response.json({ ok: true }); } export function POST() { return Response.json({ ok: true }); }";
    assert!(!warns(guarded_then_unguarded, TEST_ROUTE));

    let two_unguarded = "export function GET() { return Response.json({ ok: true }); } export function POST() { return Response.json({ ok: true }); }";
    let hits = check(two_unguarded, TEST_ROUTE)
        .into_iter()
        .filter(|v| v.rule == rule_id::TEST_ENDPOINT_PROD_GUARD)
        .count();
    assert_eq!(
        hits, 1,
        "absence is reported once per file, not per handler"
    );
}

// T-17: keyword match is case-insensitive, so a `Test` route folder on a
// case-sensitive filesystem is still caught
#[test]
fn uppercase_keyword_segment_warns() {
    let code = "export function GET() { return Response.json({ ok: true }); }";
    assert!(warns(code, "/src/app/api/Test/route.ts"));
}
