//! Pair manifest: before/after fixture pairs per enrolled rule and scenario.
//!
//! Bodies live in `fixtures/{rule}.{scenario}.{before,after}.txt`, bound at
//! compile time; a missing fixture is a build error, not a silent hole.
//! Expected counts state the exact classification split the pair produces.

use super::PairSample;

/// 1 行 = 1 pair: before / after fixture を compile 時に束ねる。
macro_rules! pairs {
    ( $( $rule:literal / $scenario:literal at $path:literal => demotes: $d:literal, blocks: $b:literal; )* ) => {
        pub(super) const PAIRS: &[PairSample] = &[
            $(
                PairSample {
                    rule: $rule,
                    scenario: $scenario,
                    path: $path,
                    before: include_str!(concat!(
                        "fixtures/", $rule, ".", $scenario, ".before.txt"
                    )),
                    after: include_str!(concat!(
                        "fixtures/", $rule, ".", $scenario, ".after.txt"
                    )),
                    expected_demoted: $d,
                    expected_blocking: $b,
                },
            )*
        ];
    };
}

pairs! {
    "eval" / "preserved" at "/src/app.ts" => demotes: 1, blocks: 0;
    "eval" / "added" at "/src/app.ts" => demotes: 1, blocks: 1;
    "eval" / "surplus-copy" at "/src/app.ts" => demotes: 1, blocks: 1;
    "eval" / "swap" at "/src/app.ts" => demotes: 1, blocks: 0;
    "eval" / "replaced" at "/src/app.ts" => demotes: 0, blocks: 1;
    "eval" / "payload-swap" at "/src/app.ts" => demotes: 0, blocks: 0;
    "raw-html" / "preserved" at "/src/app.ts" => demotes: 1, blocks: 0;
    "raw-html" / "added" at "/src/app.ts" => demotes: 1, blocks: 1;
    "raw-html" / "surplus-copy" at "/src/app.ts" => demotes: 1, blocks: 1;
    "raw-html" / "swap" at "/src/app.ts" => demotes: 0, blocks: 1;
    "raw-html" / "replaced" at "/src/app.ts" => demotes: 0, blocks: 1;
    "raw-html" / "payload-swap" at "/src/app.ts" => demotes: 0, blocks: 1;
}
