use super::super::check;
use crate::analysis::ast::with_parsed_program;
use crate::rules::rule_id;

fn assert_postmessage_fires(code: &str) {
    let v = check(code, "/src/page.ts");
    let hits: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::POSTMESSAGE_ORIGIN_MISSING)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected fire for: {code}\nviolations: {v:?}"
    );
}

fn assert_postmessage_silent(code: &str) {
    let v = check(code, "/src/page.ts");
    assert!(
        v.iter()
            .all(|x| x.rule != rule_id::POSTMESSAGE_ORIGIN_MISSING),
        "expected silent for: {code}\nviolations: {v:?}"
    );
}

#[test]
fn postmessage_origin_missing_fires_on_window_arrow_without_origin_check() {
    assert_postmessage_fires(
        "window.addEventListener('message', (event) => { processData(event.data); });",
    );
}

#[test]
fn postmessage_origin_missing_fires_on_bare_addeventlistener() {
    assert_postmessage_fires("addEventListener('message', (event) => { handle(event.data); });");
}

#[test]
fn postmessage_origin_missing_fires_on_self_addeventlistener() {
    assert_postmessage_fires("self.addEventListener('message', (e) => { handle(e.data); });");
}

#[test]
fn postmessage_origin_missing_fires_on_function_expression_handler() {
    assert_postmessage_fires(
        "window.addEventListener('message', function (e) { handle(e.data); });",
    );
}

#[test]
fn postmessage_origin_missing_fires_with_alternative_param_name() {
    assert_postmessage_fires("window.addEventListener('message', (msg) => { handle(msg.data); });");
}

#[test]
fn postmessage_origin_missing_silent_on_origin_guard() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { if (event.origin !== 'https://x.example') return; processData(event.data); });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_allowlist_check() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { const ALLOWED = ['https://a.example']; if (!ALLOWED.includes(event.origin)) return; processData(event.data); });",
    );
}

// Issue letter: bare origin reference is enough for advisory pass even if
// actual validation isn't proven. Keeps scope narrow.
#[test]
fn postmessage_origin_missing_silent_on_origin_reference_only() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { console.log(event.origin); processData(event.data); });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_computed_origin_access() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { if (event['origin'] !== 'https://x') return; });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_body_destructure() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { const { origin, data } = event; if (origin !== 'https://x') return; handle(data); });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_body_destructure_renamed() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { const { origin: o, data } = event; if (o !== 'https://x') return; handle(data); });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_assignment_destructure() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { let origin, data; ({ origin, data } = event); if (origin !== 'https://x') return; });",
    );
}

// Param-side destructure that pulls out `origin` counts as an origin-check
// hint; silent keeps the false-positive rate low.
#[test]
fn postmessage_origin_missing_silent_on_param_destructure() {
    assert_postmessage_silent(
        "window.addEventListener('message', ({ origin, data }) => { if (origin !== 'https://x') return; handle(data); });",
    );
}

// External handler reference is out of scope: 1-file scope cannot follow
// the body. Issue states this explicitly.
#[test]
fn postmessage_origin_missing_silent_on_external_handler() {
    assert_postmessage_silent(
        "function onMsg(e) { handle(e.data); }\nwindow.addEventListener('message', onMsg);",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_non_message_event() {
    assert_postmessage_silent("window.addEventListener('click', (event) => { handle(event); });");
}

#[test]
fn postmessage_origin_missing_silent_on_zero_arg_callback() {
    assert_postmessage_silent("window.addEventListener('message', () => {});");
}

// Issue letter limits the receiver to `window` / `self` / bare global.
// `globalThis.addEventListener` is out of scope by Issue letter; silent
// until expanded with explicit user request.
#[test]
fn postmessage_origin_missing_silent_on_globalthis_addeventlistener() {
    assert_postmessage_silent(
        "globalThis.addEventListener('message', (e) => { handle(e.data); });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_worker_addeventlistener() {
    assert_postmessage_silent(
        "const w = new Worker('w.js');\nw.addEventListener('message', (e) => { handle(e.data); });",
    );
}

#[test]
fn postmessage_origin_missing_fires_for_each_violating_listener() {
    let code = "window.addEventListener('message', (e) => { handle(e.data); });\nself.addEventListener('message', (m) => { handle(m.data); });";
    let v = check(code, "/src/page.ts");
    let hits: Vec<_> = v
        .iter()
        .filter(|x| x.rule == rule_id::POSTMESSAGE_ORIGIN_MISSING)
        .collect();
    assert_eq!(hits.len(), 2, "expected two violations: {v:?}");
}

#[test]
fn postmessage_origin_missing_fires_on_param_destructure_without_origin() {
    assert_postmessage_fires(
        "window.addEventListener('message', ({ data }) => { document.body.innerHTML = data; });",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_param_destructure_origin_only() {
    assert_postmessage_silent(
        "window.addEventListener('message', ({ origin }) => { if (origin !== 'https://x') return; });",
    );
}

// Handler signatures with no origin-check path (array destructure, rest
// pattern, etc.) fire conservatively: no recognized validation path.
#[test]
fn postmessage_origin_missing_fires_on_param_array_pattern() {
    assert_postmessage_fires(
        "window.addEventListener('message', ([first]) => { handle(first); });",
    );
}

#[test]
fn postmessage_origin_missing_fires_on_window_onmessage_without_origin() {
    assert_postmessage_fires(
        "window.onmessage = (event) => { document.body.innerHTML = event.data; };",
    );
}

#[test]
fn postmessage_origin_missing_fires_on_self_onmessage_without_origin() {
    assert_postmessage_fires("self.onmessage = (event) => { handle(event.data); };");
}

#[test]
fn postmessage_origin_missing_silent_on_window_onmessage_with_origin_check() {
    assert_postmessage_silent(
        "window.onmessage = (event) => { if (event.origin !== 'https://x') return; handle(event.data); };",
    );
}

#[test]
fn postmessage_origin_missing_fires_on_window_onmessage_function_expression() {
    assert_postmessage_fires("window.onmessage = function (event) { handle(event.data); };");
}

#[test]
fn postmessage_origin_missing_silent_on_window_onmessage_param_destructure_origin_only() {
    assert_postmessage_silent(
        "window.onmessage = ({ origin }) => { if (origin !== 'https://x') return; };",
    );
}

#[test]
fn postmessage_origin_missing_fires_on_window_onmessage_param_destructure_without_origin() {
    assert_postmessage_fires(
        "window.onmessage = ({ data }) => { document.body.innerHTML = data; };",
    );
}

// Receiver allowlist is `window` / `self` / bare global only; `globalThis`
// is intentionally excluded so the boundary matches `addEventListener`.
#[test]
fn postmessage_origin_missing_silent_on_globalthis_onmessage() {
    assert_postmessage_silent("globalThis.onmessage = (event) => { handle(event.data); };");
}

// Nested function shadows the handler param. The inner `event.origin`
// reads belong to the inner binding, so the outer handler still lacks an
// origin check and must fire.
#[test]
fn postmessage_origin_missing_fires_on_nested_function_shadow() {
    assert_postmessage_fires(
        "window.addEventListener('message', (event) => { function inner(event) { if (event.origin !== 'https://x') return; } inner(event); });",
    );
}

// Arrow-function variant of the nested shadow case; verifies the same
// SymbolId-separation works for `const inner = (event) => ...`.
#[test]
fn postmessage_origin_missing_fires_on_nested_arrow_shadow() {
    assert_postmessage_fires(
        "window.addEventListener('message', (event) => { const inner = (event) => { if (event.origin !== 'https://x') return; }; inner(event); });",
    );
}

// Destructuring rename `({ origin: trusted }) => ...` extracts origin at
// the param boundary; pattern_destructures_origin covers it without
// requiring a body reference.
#[test]
fn postmessage_origin_missing_silent_on_destructured_origin_rename() {
    assert_postmessage_silent(
        "window.addEventListener('message', ({ origin: trusted, data }) => { if (trusted !== 'https://x') return; handle(data); });",
    );
}

// Block-scoped shadow must not invalidate the outer origin check. The
// inner `const event` is a separate symbol; the outer `event.origin`
// resolves to the handler param.
#[test]
fn postmessage_origin_missing_silent_on_shadowed_event_in_inner_block() {
    assert_postmessage_silent(
        "window.addEventListener('message', (event) => { if (debug) { const event = { origin: 'local' }; console.log(event.origin); } if (event.origin !== 'https://x') return; handle(event.data); });",
    );
}

// Block-scoped shadow with origin reference inside the block only: the
// inner `event.origin` belongs to the inner symbol, so the outer handler
// has no origin check and must fire. Discriminator that block-scope
// creates a separate symbol (vs. the same-scope SyntaxError case).
#[test]
fn postmessage_origin_missing_fires_on_block_scope_shadow_inner_only() {
    assert_postmessage_fires(
        "window.addEventListener('message', (event) => { if (debug) { const event = { origin: 'attacker' }; console.log(event.origin); } handle(event.data); });",
    );
}

// `var event = ...` is a legal function-scoped re-declaration that reuses
// the param's SymbolId. Later `event.origin` resolves to the same symbol
// but the value is attacker-controlled; the rule must invalidate the
// origin check and fire.
#[test]
fn postmessage_origin_missing_fires_on_var_clobber_of_param() {
    assert_postmessage_fires(
        "window.addEventListener('message', (event) => { var event = { origin: 'attacker' }; if (event.origin !== 'https://x') return; handle(event.data); });",
    );
}

// #293: SemanticBuilder is built only when `requires_semantic` pre-scans an
// identifier-param message handler. The pre-scan must walk the full tree, not
// just top-level statements: a validating handler nested inside an IIFE still
// needs `scoping` to resolve `event.origin`. If the pre-scan missed it, the
// build would be skipped, `symbol_id` would be absent, and the handler would
// over-fire as a false positive.
#[test]
fn postmessage_origin_missing_silent_on_validating_handler_nested_in_iife() {
    assert_postmessage_silent(
        "(function () { window.addEventListener('message', (event) => { if (event.origin !== 'https://x') return; handle(event.data); }); })();",
    );
}

#[test]
fn postmessage_origin_missing_fires_on_bare_onmessage_without_origin() {
    assert_postmessage_fires("onmessage = (event) => { handle(event.data); };");
}

// `requires_semantic` is the gate that decides whether the (expensive)
// SemanticBuilder runs. The whole safety argument of the lazy build rests on
// it returning `true` for every identifier-param handler: if it ever returned
// `false` for one, `scoping` would be `None`, `handler_validates_origin` would
// return `false`, and a validating handler would fire as a false positive
// (never a suppressed finding — but a regression nonetheless). These assert the
// gate decision directly, so a future break in `note_handler` (e.g. it stops
// recognizing `BindingIdentifier` params) fails here rather than silently
// degrading the rule. The nesting cases also confirm the `visit_statement`
// early-exit guard does not stop descent before the handler is reached.
fn requires_semantic_for(code: &str) -> bool {
    with_parsed_program(code, "/src/page.ts", |program, _| {
        super::requires_semantic(program)
    })
    .expect("parse should succeed for test inputs")
}

#[test]
fn requires_semantic_true_for_identifier_param_addeventlistener() {
    assert!(requires_semantic_for(
        "window.addEventListener('message', (event) => { handle(event.data); });"
    ));
}

#[test]
fn requires_semantic_true_for_identifier_param_onmessage_assignment() {
    assert!(requires_semantic_for(
        "window.onmessage = (event) => { handle(event.data); };"
    ));
}

#[test]
fn requires_semantic_false_for_object_pattern_param() {
    assert!(!requires_semantic_for(
        "window.addEventListener('message', ({ data }) => { handle(data); });"
    ));
}

#[test]
fn requires_semantic_false_for_zero_arg_handler() {
    assert!(!requires_semantic_for(
        "window.addEventListener('message', () => {});"
    ));
}

#[test]
fn requires_semantic_false_for_no_message_handler() {
    assert!(!requires_semantic_for(
        "window.addEventListener('click', (event) => { handle(event); });"
    ));
}

#[test]
fn requires_semantic_false_for_handler_less_file() {
    assert!(!requires_semantic_for(
        "const x = 1; function f(y) { return y + 1; }"
    ));
}

#[test]
fn requires_semantic_true_for_identifier_handler_nested_in_iife() {
    assert!(requires_semantic_for(
        "(function () { window.addEventListener('message', (event) => { handle(event.data); }); })();"
    ));
}

#[test]
fn requires_semantic_true_for_identifier_onmessage_nested_in_iife() {
    assert!(requires_semantic_for(
        "(function () { window.onmessage = (event) => { handle(event.data); }; })();"
    ));
}

#[test]
fn requires_semantic_true_for_identifier_handler_in_named_function() {
    assert!(requires_semantic_for(
        "function setup() { window.addEventListener('message', (event) => { handle(event.data); }); }",
    ));
}

#[test]
fn requires_semantic_true_for_identifier_handler_in_class_method() {
    assert!(requires_semantic_for(
        "class App { init() { window.addEventListener('message', (event) => { handle(event.data); }); } }",
    ));
}

#[test]
fn postmessage_origin_missing_silent_on_bare_onmessage_with_origin_check() {
    assert_postmessage_silent(
        "onmessage = (event) => { if (event.origin !== 'https://x') return; handle(event.data); };",
    );
}

// #317: end-to-end (`check()` → lazy SemanticBuilder → fire/silent) regression
// guards for two container shapes that the pre-scan / SecurityVisitor walk
// descends but no e2e test pinned: class methods and try blocks. The fire+silent
// pair per shape is the assertion, not redundancy — the fire case proves the
// walker reaches the handler, the silent case proves origin resolution works
// once reached. A silent test alone could pass by the handler never being
// reached (silent by accident); the paired fire test rules that out.
//
// object-literal methods (`{ init() { window.addEventListener(...) } }`) are the
// same equivalence class as class methods: both descend through a normal
// function body and resolve `event.origin` by `SymbolId` (nesting-independent),
// so they are not pinned separately.
#[test]
fn postmessage_origin_missing_fires_on_handler_in_class_method() {
    assert_postmessage_fires(
        "class App { init() { window.addEventListener('message', (event) => { handle(event.data); }); } }",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_validating_handler_in_class_method() {
    assert_postmessage_silent(
        "class App { init() { window.addEventListener('message', (event) => { if (event.origin !== 'https://x') return; handle(event.data); }); } }",
    );
}

// try block exercises the `walk_try_statement → .block` dispatch arm. Unlike the
// other container shapes it has no gate-level pin either, so it is the case most
// likely to surface a real descent gap if the pre-scan ever stops walking
// `TryStatement`.
#[test]
fn postmessage_origin_missing_fires_on_handler_in_try_block() {
    assert_postmessage_fires(
        "try { window.addEventListener('message', (event) => { handle(event.data); }); } catch (e) { report(e); }",
    );
}

#[test]
fn postmessage_origin_missing_silent_on_validating_handler_in_try_block() {
    assert_postmessage_silent(
        "try { window.addEventListener('message', (event) => { if (event.origin !== 'https://x') return; handle(event.data); }); } catch (e) { report(e); }",
    );
}
