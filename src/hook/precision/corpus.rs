//! Corpus table: one should-fire and one should-not-fire sample per
//! first-party `rule_id`. What separates a pair is the fixture content, or
//! for path-based rules the virtual path.
//!
//! Bodies live in `fixtures/{rule_id}.{fire,clean}.txt`, bound at compile
//! time; a missing fixture is a build error, not a silent corpus hole.
//! Paths are the virtual hook-contract paths each sample is checked under.

use super::{CorpusSample, Expectation};

/// 1 行 = 1 `rule_id`: fire fixture + clean fixture の 2 sample を展開する。
macro_rules! samples {
    ( $( $rule:literal => fire: $fire_path:literal, clean: $clean_path:literal; )* ) => {
        pub(super) const SAMPLES: &[CorpusSample] = &[
            $(
                CorpusSample {
                    rule: $rule,
                    path: $fire_path,
                    content: include_str!(concat!("fixtures/", $rule, ".fire.txt")),
                    expectation: Expectation::Fire,
                },
                CorpusSample {
                    rule: $rule,
                    path: $clean_path,
                    content: include_str!(concat!("fixtures/", $rule, ".clean.txt")),
                    expectation: Expectation::Clean,
                },
            )*
        ];
    };
}

samples! {
    "sensitive-file" => fire: "/project/.env", clean: "/src/app.ts";
    "architecture" => fire: "/src/utils/format.ts", clean: "/src/pages/Home.tsx";
    "naming-convention" => fire: "/src/types.ts", clean: "/src/types.ts";
    "transaction-boundary" => fire: "/src/usecases/handler.ts", clean: "/src/usecases/handler.ts";
    "security" => fire: "/src/app.ts", clean: "/src/app.ts";
    "crypto-weak" => fire: "/src/hash.ts", clean: "/src/hash.ts";
    "generated-file" => fire: "/src/api/client.generated.ts", clean: "/src/components/Button.tsx";
    "test-location" => fire: "/project/src/utils/helper.test.ts", clean: "/project/tests/utils/helper.test.ts";
    "dom-access" => fire: "/src/components/App.tsx", clean: "/src/components/App.tsx";
    "sync-io" => fire: "/src/loader.ts", clean: "/src/loader.ts";
    "bundle-size" => fire: "/src/util.ts", clean: "/src/util.ts";
    "test-assertion" => fire: "/src/utils.test.ts", clean: "/src/utils.test.ts";
    "flaky-test" => fire: "/src/utils.test.ts", clean: "/src/utils.test.ts";
    "sensitive-logging" => fire: "/src/auth.ts", clean: "/src/auth.ts";
    "eval" => fire: "/src/app.ts", clean: "/src/app.ts";
    "hardcoded-secret" => fire: "/src/api.ts", clean: "/src/api.ts";
    "http-resource" => fire: "/src/api.ts", clean: "/src/api.ts";
    "raw-html" => fire: "/src/render.ts", clean: "/src/render.ts";
    "open-redirect" => fire: "/src/router.ts", clean: "/src/router.ts";
    "err-stack-exposure" => fire: "/app/api/route.ts", clean: "/app/api/route.ts";
    "child-process-injection" => fire: "/app/api/route.ts", clean: "/app/api/route.ts";
    "no-use-effect" => fire: "/src/components/App.tsx", clean: "/src/components/App.tsx";
    "non-literal-fs-path" => fire: "/app/api/route.ts", clean: "/app/api/route.ts";
    "bidi-characters" => fire: "/src/app.ts", clean: "/src/app.ts";
    "unsafe-regex" => fire: "/src/parse.ts", clean: "/src/parse.ts";
    "non-literal-require" => fire: "/app/api/route.ts", clean: "/app/api/route.ts";
    "env-var-fallback" => fire: "/src/config.ts", clean: "/src/config.ts";
    "dangerous-inner-html" => fire: "/src/components/Post.tsx", clean: "/src/components/Post.tsx";
    "math-random-insecure" => fire: "/src/token.ts", clean: "/src/animation.ts";
    "cot-leakage-marker" => fire: "/src/log.ts", clean: "/src/log.ts";
    "prototype-pollution" => fire: "/src/obj.ts", clean: "/src/obj.ts";
    "sqli-concat" => fire: "/src/db.ts", clean: "/src/db.ts";
    "cors-wildcard" => fire: "/app/api/route.ts", clean: "/app/api/route.ts";
    "unsafe-html-injection" => fire: "/src/page.ts", clean: "/src/page.ts";
    "service-worker-scope-root" => fire: "/src/sw-register.ts", clean: "/src/sw-register.ts";
    "jwt-client-decode" => fire: "/src/auth.ts", clean: "/src/auth.ts";
    "client-env-public-leak" => fire: "/src/components/Profile.tsx", clean: "/src/components/Profile.tsx";
    "ssr-secret-bleed" => fire: "/pages/dashboard.tsx", clean: "/pages/dashboard.tsx";
    "postmessage-origin-missing" => fire: "/src/page.ts", clean: "/src/page.ts";
    "excessive-nesting" => fire: "/src/app.ts", clean: "/src/app.ts";
    "test-endpoint-prod-guard" => fire: "/app/api/test-setup/route.ts", clean: "/app/api/test-setup/route.ts";
}
