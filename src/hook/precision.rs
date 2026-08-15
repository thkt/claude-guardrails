//! Per-rule precision / recall / latency measurement harness (test-only).
//!
//! Drives the production pipeline (`collect_violations`) with corpus samples,
//! tallies per-rule confusion counts, and measures per-sample latency.
//! Fixture bodies live under `precision/fixtures/` as `.txt` files so editing
//! them does not trigger this repo's own `PreToolUse` hook; per-sample metadata
//! (`rule_id`, virtual hook path, expectation) stays in `precision/corpus.rs`.
//!
//! The snapshot test never fails on FN/FP counts (known false negatives are
//! banked in the corpus first; fixes land in later PRs with the delta visible
//! in numbers). It fails only on corpus coverage gaps and latency.

mod corpus;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use globset::GlobBuilder;

use super::collect_violations;
use crate::config::{Config, OverrideEntry};
use crate::rules::rule_id::{self, RULE_ID_CATALOG};
use crate::rules::{toggle_isolation_cases, RE_JS_FILE};

/// Whether a sample must trigger its rule (`Fire`) or stay silent (`Clean`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expectation {
    Fire,
    Clean,
}

/// One corpus entry: a virtual hook payload (path + content) pinned to the
/// `rule_id` whose detection behavior it measures.
struct CorpusSample {
    rule: &'static str,
    path: &'static str,
    content: &'static str,
    expectation: Expectation,
}

/// Per-rule confusion counts. `unexpected_fires` counts fires of this rule
/// on samples that expected a different rule; recorded for diagnostics, not
/// judged against the sample's expectation.
#[derive(Debug, Default)]
struct Tally {
    tp: u32,
    fn_count: u32,
    fp: u32,
    tn: u32,
    unexpected_fires: u32,
}

/// Production default with oxlint delegation off: the corpus covers exactly
/// the first-party `rule_id`s and must not depend on an oxlint binary.
fn harness_config() -> Config {
    let mut config = Config::default();
    config.rules.oxlint = false;
    config
}

/// Runs one sample through the production pipeline and returns the fired
/// `rule_id`s. `is_js` is derived from the sample path with the same regex
/// production applies to the hook `file_path`, so non-JS samples (e.g. the
/// sensitive-file `.env` payload) skip the AST branch exactly as production
/// does. With oxlint off the only possible note is an AST parse failure,
/// which would silently downgrade fire samples to FN, so notes fail loudly.
fn detected_rules(path: &str, content: &str, config: &Config) -> BTreeSet<String> {
    let (violations, notes) =
        collect_violations(path, content, config, None, RE_JS_FILE.is_match(path), None);
    assert!(
        notes.is_empty(),
        "pipeline notes for {path}: {notes:?} (fixture no longer parses?)"
    );
    violations.into_iter().map(|v| v.rule).collect()
}

/// Tallies the corpus sample by sample. The counting unit is the sample,
/// judged only on its own expected `rule_id` (TP/FN for fire samples, FP/TN
/// for clean samples); fires of other rules land in their `unexpected_fires`.
fn tally_corpus(samples: &[CorpusSample], config: &Config) -> BTreeMap<String, Tally> {
    let mut tallies: BTreeMap<String, Tally> = RULE_ID_CATALOG
        .iter()
        .map(|rule| ((*rule).to_owned(), Tally::default()))
        .collect();
    for sample in samples {
        let detected = detected_rules(sample.path, sample.content, config);
        let own_fired = detected.contains(sample.rule);
        // Block scopes the `entry` borrow so the unexpected-fires loop below
        // can re-borrow `tallies`.
        {
            let entry = tallies.entry(sample.rule.to_owned()).or_default();
            match (sample.expectation, own_fired) {
                (Expectation::Fire, true) => entry.tp += 1,
                (Expectation::Fire, false) => entry.fn_count += 1,
                (Expectation::Clean, true) => entry.fp += 1,
                (Expectation::Clean, false) => entry.tn += 1,
            }
        }
        for other in detected {
            if other != sample.rule {
                tallies.entry(other).or_default().unexpected_fires += 1;
            }
        }
    }
    tallies
}

const LATENCY_ITERATIONS: usize = 50;

/// Median elapsed microseconds over `LATENCY_ITERATIONS` pipeline invocations.
/// The median tolerates CI runner spikes that a mean would absorb into a fail.
fn median_latency_us(path: &str, content: &str, config: &Config) -> u64 {
    let is_js = RE_JS_FILE.is_match(path);
    let mut elapsed: Vec<u128> = (0..LATENCY_ITERATIONS)
        .map(|_| {
            let start = Instant::now();
            let _ = collect_violations(path, content, config, None, is_js, None);
            start.elapsed().as_micros()
        })
        .collect();
    elapsed.sort_unstable();
    // Saturating keeps an impossibly large median failing the 10ms gate
    // loudly instead of wrapping into a passing value.
    u64::try_from(elapsed[LATENCY_ITERATIONS / 2]).unwrap_or(u64::MAX)
}

/// Worst (max) fire-sample median per toggle under its isolation config.
/// Diagnostics only: no assertion, the per-sample gate runs all rules on.
fn toggle_latency_diagnostics() -> BTreeMap<String, u64> {
    toggle_isolation_cases()
        .into_iter()
        .map(|(name, config, rules)| {
            let worst = corpus::SAMPLES
                .iter()
                .filter(|s| rules.contains(&s.rule) && s.expectation == Expectation::Fire)
                .map(|s| median_latency_us(s.path, s.content, &config))
                .max()
                .unwrap_or(0);
            (name.to_owned(), worst)
        })
        .collect()
}

/// Serializable per-rule metrics row. The JSON key for false negatives is
/// `fn`, which is a Rust keyword, hence the rename.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMetrics {
    tp: u32,
    #[serde(rename = "fn")]
    fn_count: u32,
    fp: u32,
    tn: u32,
    precision: f64,
    recall: f64,
    latency_us_median: u64,
    unexpected_fires: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsReport {
    rules: BTreeMap<String, RuleMetrics>,
    toggle_latency_us: BTreeMap<String, u64>,
    overrides: OverrideMetrics,
}

/// Defined as 1.0 when the denominator is 0: a rule with no chance to err
/// has not erred. Numerator is tp for both precision (tp / tp+fp) and
/// recall (tp / tp+fn).
fn ratio(numerator: u32, denom: u32) -> f64 {
    if denom == 0 {
        1.0
    } else {
        f64::from(numerator) / f64::from(denom)
    }
}

fn build_report(
    tallies: BTreeMap<String, Tally>,
    latencies: &BTreeMap<String, u64>,
    toggle_latency_us: BTreeMap<String, u64>,
    overrides: OverrideMetrics,
) -> MetricsReport {
    let rules = tallies
        .into_iter()
        .map(|(rule, t)| {
            let metrics = RuleMetrics {
                tp: t.tp,
                fn_count: t.fn_count,
                fp: t.fp,
                tn: t.tn,
                precision: ratio(t.tp, t.tp + t.fp),
                recall: ratio(t.tp, t.tp + t.fn_count),
                // 0 only when the caller passed no measurement for the rule
                // (ad-hoc tallies in unit tests). The snapshot test measures
                // every corpus sample, and T-266 fails the same run when a
                // rule has no samples, so 0 cannot reach CI metrics.
                latency_us_median: latencies.get(&rule).copied().unwrap_or(0),
                unexpected_fires: t.unexpected_fires,
            };
            (rule, metrics)
        })
        .collect();
    MetricsReport {
        rules,
        toggle_latency_us,
        overrides,
    }
}

/// Human-readable per-rule table for stderr (used when no JSON path is set).
fn render_metrics_table(report: &MetricsReport) -> String {
    let mut out = String::from(
        "rule                        tp  fn  fp  tn  precision  recall  latency_us  unexpected\n",
    );
    for (rule, m) in &report.rules {
        let _ = writeln!(
            out,
            "{rule:<27} {tp:>3} {fn_count:>3} {fp:>3} {tn:>3}  {precision:>9.2}  {recall:>6.2}  {latency:>10}  {unexpected:>10}",
            tp = m.tp,
            fn_count = m.fn_count,
            fp = m.fp,
            tn = m.tn,
            precision = m.precision,
            recall = m.recall,
            latency = m.latency_us_median,
            unexpected = m.unexpected_fires,
        );
    }
    out
}

fn write_metrics_json(report: &MetricsReport, path: &Path) -> io::Result<()> {
    let json = serde_json::to_string_pretty(report).expect("metrics report serializes");
    fs::write(path, json)
}

/// CI seam: with `GUARDRAILS_METRICS_OUT` set the snapshot lands as JSON at
/// that path (consumed by the precision delta gate); without it the table
/// goes to stderr for local runs.
fn emit_metrics(report: &MetricsReport) {
    if let Some(path) = env::var_os("GUARDRAILS_METRICS_OUT") {
        let path = PathBuf::from(path);
        write_metrics_json(report, &path).expect("write metrics JSON");
        eprintln!("guardrails: metrics written to {}", path.display());
    } else {
        eprint!("{}", render_metrics_table(report));
    }
}

/// Rules from `catalog` lacking a fire and/or clean sample in `samples`.
/// Pure so the gate itself is testable with planted gaps.
fn missing_corpus_coverage(catalog: &[&str], samples: &[CorpusSample]) -> Vec<String> {
    let mut missing = Vec::new();
    for rule in catalog {
        let has_fire = samples
            .iter()
            .any(|s| s.rule == *rule && s.expectation == Expectation::Fire);
        let has_clean = samples
            .iter()
            .any(|s| s.rule == *rule && s.expectation == Expectation::Clean);
        if !has_fire {
            missing.push(format!("{rule} (fire)"));
        }
        if !has_clean {
            missing.push(format!("{rule} (clean)"));
        }
    }
    missing
}

/// Rules whose firing cannot be exercised through the `(path, content)` corpus
/// harness, so the coverage gate below excludes them. `invariant` is stateful:
/// it fires only with a reconstructed `structured_full` document and an
/// `.invariants.json` on disk at the git root, neither of which the corpus model
/// supplies (`detected_rules` passes `structured_full = None`). Its coverage
/// lives in `invariant/tests.rs` (T-1..T-21, disk-backed + pure conformance) and
/// the end-to-end `hook/tests.rs::json_edit_fires_invariant_violation_end_to_end`
/// (T-22), not here. `config-guard` needs a git root to match against, and
/// `harness_config` builds a `Config` without one, so no corpus path reaches
/// it; its coverage lives in `rules/config_guard/tests.rs` and
/// `tests/cli/config.rs`. `invariant-guard` needs the same disk-backed
/// `.invariants.json` pin file at the git root as `invariant` (it judges a
/// weakening edit to that same declaration file); its coverage lives in
/// `rules/invariant_guard/tests.rs`. Same allowlist precedent as
/// `UNREGISTERED_RULE_IDS`.
const CORPUS_EXEMPT: &[&str] = &[
    rule_id::INVARIANT,
    rule_id::CONFIG_GUARD,
    rule_id::INVARIANT_GUARD,
];

// T-266: 全 first-party rule_id に should-fire / should-not-fire 両 sample が存在する (corpus 網羅 gate)。
#[test]
fn corpus_covers_every_rule_with_fire_and_clean_samples() {
    let covered: Vec<&str> = RULE_ID_CATALOG
        .iter()
        .copied()
        .filter(|rule| !CORPUS_EXEMPT.contains(rule))
        .collect();
    let missing = missing_corpus_coverage(&covered, corpus::SAMPLES);
    assert!(
        missing.is_empty(),
        "rules missing corpus samples: {missing:?}"
    );
}

// T-266 negative: sample 欠落を植えた catalog で gate が欠落側を名指しで列挙する。
#[test]
fn corpus_coverage_gate_detects_planted_gap() {
    let samples = [CorpusSample {
        rule: "eval",
        path: "/src/app.ts",
        content: "eval(x);\n",
        expectation: Expectation::Fire,
    }];
    let missing = missing_corpus_coverage(&["eval", "raw-html"], &samples);
    assert_eq!(
        missing,
        vec!["eval (clean)", "raw-html (fire)", "raw-html (clean)"]
    );
}

// T-266 逆向き: corpus が catalog に無い rule_id を参照しない (typo gate)。
#[test]
fn corpus_rule_ids_exist_in_catalog() {
    for sample in corpus::SAMPLES {
        assert!(
            RULE_ID_CATALOG.contains(&sample.rule),
            "corpus sample references unknown rule_id {}",
            sample.rule
        );
    }
}

// fixture 腐敗 gate: 各 corpus sample が自身の expectation どおり振る舞う。
// fixture 編集で fire が沈黙 (FN 化) / clean が発火 (FP 化) すると metrics
// snapshot は数値が動くだけで fail しないため、ここで sample 単位に固定する。
// known-FN を corpus に先積みする運用が始まったら CorpusSample に opt-out
// flag を足す (現状 known-FN は 0 件なので未導入)。
#[test]
fn corpus_fixtures_match_their_fire_clean_expectation() {
    let config = harness_config();
    let mut broken = Vec::new();
    for sample in corpus::SAMPLES {
        let fired = detected_rules(sample.path, sample.content, &config).contains(sample.rule);
        let matches = match sample.expectation {
            Expectation::Fire => fired,
            Expectation::Clean => !fired,
        };
        if !matches {
            broken.push(format!("{} ({:?})", sample.rule, sample.expectation));
        }
    }
    assert!(
        broken.is_empty(),
        "fixtures contradicting their expectation: {broken:?}"
    );
}

// toggle isolation mapping が first-party catalog を過不足なく覆う drift gate。
#[test]
fn toggle_isolation_mapping_covers_catalog_exactly() {
    let mapped: BTreeSet<&str> = toggle_isolation_cases()
        .iter()
        .flat_map(|(_, _, rules)| rules.iter().copied())
        .collect();
    let catalog: BTreeSet<&str> = RULE_ID_CATALOG.iter().copied().collect();
    assert_eq!(mapped, catalog);
}

// #303: hook.rs の AST skip-guard (`lint_with_ast`) と dispatch アームは同じ AST
// フラグ集合を二重に列挙する。新 AST ルールを片方にだけ足すと、そのルールだけを
// 有効化し他を全 off にした構成で parse がスキップ (skip-guard 漏れ) または check
// 未呼び出し (dispatch 漏れ) となり、Fire sample が黙って FN に落ちる。既定の
// all-on 構成では他フラグの OR で skip-guard が真のままになるためこの drift は
// `corpus_fixtures_match_their_fire_clean_expectation` を素通りする。
//
// 各トグルを単独有効化 (all-off + 1 toggle on) し、そのトグルが gate する全 rule の
// Fire sample が発火することを assert して、その silent drift を hot-path 改変ゼロで
// 閉じる。AST 系に限らず全トグル一様で、line rule は単独でも独立に発火するため green。
#[test]
fn every_toggle_fires_its_rules_under_single_toggle_isolation() {
    let mut missed = Vec::new();
    for (name, config, rules) in toggle_isolation_cases() {
        for sample in corpus::SAMPLES
            .iter()
            .filter(|s| rules.contains(&s.rule) && s.expectation == Expectation::Fire)
        {
            if !detected_rules(sample.path, sample.content, &config).contains(sample.rule) {
                missed.push(format!("{name}/{} ({})", sample.rule, sample.path));
            }
        }
    }
    assert!(
        missed.is_empty(),
        "fire samples not detected under single-toggle isolation \
         (skip-guard/dispatch flag drift?): {missed:?}"
    );
}

// U-002 (#449): 上の every_toggle_fires_... の逆向き。single-toggle isolation は
// 「そのtoggleをonにした構成で、数える rule_id が発火するか」を見る。ここでは
// 「そのtoggleをoffにした構成で、数える rule_id が発火しないか」を見て、
// toggle_rule_id_count の引き算 (TOGGLE_RULE_ID_COUNT_EXCEPTIONS_*) が実際の
// 発火と食い違ったら落ちる。TOGGLE_RULE_IDS 自体のmembership (一覧) はどちらの
// テストでも変えない。

// T-553: 数に含まれる rule_id は、その toggle を off にすると fire サンプルから出ない
#[test]
fn 数に含まれる_rule_id_は_その_toggle_を_off_にすると_fire_サンプルから出ない() {
    let mut config = Config::default();
    config.rules.crypto_weak = false;
    let sample = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == rule_id::CRYPTO_WEAK && s.expectation == Expectation::Fire)
        .expect("crypto-weak の fire サンプルが corpus に存在しない");
    let detected = detected_rules(sample.path, sample.content, &config);
    assert!(
        !detected.contains(rule_id::CRYPTO_WEAK),
        "cryptoWeak を off にしても crypto-weak が発火した: {detected:?}"
    );
}

// T-554: 例外に挙げた rule_id は、その toggle を off にしても出続ける
#[test]
fn 例外に挙げた_rule_id_は_その_toggle_を_off_にしても出続ける() {
    let mut config = Config::default();
    config.rules.ast_security = false;
    let sample = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == rule_id::EXCESSIVE_NESTING && s.expectation == Expectation::Fire)
        .expect("excessive-nesting の fire サンプルが corpus に存在しない");
    let detected = detected_rules(sample.path, sample.content, &config);
    assert!(
        detected.contains(rule_id::EXCESSIVE_NESTING),
        "astSecurity を off にしたら excessive-nesting が発火しなくなった \
         (unconditional exception が崩れた?): {detected:?}"
    );
}

// T-598: 同じ rule_id を出す emitter が 2 つあるとき、片方の toggle を off に
// しても出続ける。この前提が崩れると MULTI_EMITTER の引き算が過剰になる。
#[test]
fn 複数の_emitter_を持つ_rule_id_は_片方の_toggle_を_off_にしても出続ける() {
    let mut config = Config::default();
    config.rules.security = false;
    let detected = detected_rules("src/app.ts", "target.postMessage(payload, '*');\n", &config);
    assert!(
        detected.contains(rule_id::SECURITY),
        "security を off にしたら postMessage 経由の security が発火しなくなった \
         (multi-emitter exception が崩れた?): {detected:?}"
    );
}

// T-267: should-fire sample は検出で tp、未検出で fn に計上される。
#[test]
fn fire_samples_tally_tp_when_detected_and_fn_when_missed() {
    let config = harness_config();
    let samples = [
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Fire,
        },
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "export const x = 1;\n",
            expectation: Expectation::Fire,
        },
    ];
    let tallies = tally_corpus(&samples, &config);
    assert_eq!(tallies["eval"].tp, 1);
    assert_eq!(tallies["eval"].fn_count, 1);
}

// T-268: should-not-fire sample は発火で fp、沈黙で tn に計上される。
#[test]
fn clean_samples_tally_fp_when_fired_and_tn_when_silent() {
    let config = harness_config();
    let samples = [
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Clean,
        },
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "export const x = 1;\n",
            expectation: Expectation::Clean,
        },
    ];
    let tallies = tally_corpus(&samples, &config);
    assert_eq!(tallies["eval"].fp, 1);
    assert_eq!(tallies["eval"].tn, 1);
}

// T-272: 期待外 rule の発火は firing rule の unexpected_fires に入り、fp には入らない。
#[test]
fn off_target_fires_count_as_unexpected_not_fp() {
    let config = harness_config();
    let samples = [CorpusSample {
        rule: "eval",
        path: "/src/app.ts",
        content: "eval(userInput);\nel.innerHTML = userInput;\n",
        expectation: Expectation::Fire,
    }];
    let tallies = tally_corpus(&samples, &config);
    assert_eq!(tallies["eval"].tp, 1);
    assert_eq!(tallies["unsafe-html-injection"].unexpected_fires, 1);
    assert_eq!(tallies["unsafe-html-injection"].fp, 0);
}

// T-273: AST 系 rule の should-fire sample が検出される (line rules に加え AST 経路が実行された証明)。
#[test]
fn ast_rule_fire_sample_detected_via_ast_path() {
    let config = harness_config();
    let sample = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == "prototype-pollution" && s.expectation == Expectation::Fire)
        .expect("corpus has a prototype-pollution fire sample");
    let detected = detected_rules(sample.path, sample.content, &config);
    assert!(
        detected.contains("prototype-pollution"),
        "AST path did not fire; detected: {detected:?}"
    );
}

// T-269: tp=1, fp=1, fn=0 から precision 0.5 / recall 1.0 を計算し、JSON writer と stderr 表が全項目を持つ。
#[test]
fn metrics_computation_and_outputs_carry_all_counts() {
    let config = harness_config();
    let samples = [
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Fire,
        },
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Clean,
        },
    ];
    let tallies = tally_corpus(&samples, &config);
    let report = build_report(
        tallies,
        &BTreeMap::new(),
        BTreeMap::new(),
        OverrideMetrics::default(),
    );
    let eval = &report.rules["eval"];
    assert_eq!(eval.tp, 1);
    assert_eq!(eval.fp, 1);
    assert_eq!(eval.fn_count, 0);
    assert!((eval.precision - 0.5).abs() < f64::EPSILON);
    assert!((eval.recall - 1.0).abs() < f64::EPSILON);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("metrics.json");
    write_metrics_json(&report, &path).expect("write json");
    let raw = fs::read_to_string(&path).expect("read back");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
    let row = &parsed["rules"]["eval"];
    assert_eq!(row["tp"], 1);
    assert_eq!(row["fn"], 0);
    assert_eq!(row["fp"], 1);
    assert_eq!(row["precision"], 0.5);
    assert_eq!(row["recall"], 1.0);
    assert!(row.get("latency_us_median").is_some());
    assert!(row.get("unexpected_fires").is_some());
    assert!(parsed.get("toggle_latency_us").is_some());

    let table = render_metrics_table(&report);
    let eval_row = table
        .lines()
        .find(|line| line.starts_with("eval"))
        .expect("eval row in table");
    assert!(
        eval_row.contains("0.50"),
        "precision 0.50 missing from eval row: {eval_row}"
    );
    assert!(
        eval_row.contains("1.00"),
        "recall 1.00 missing from eval row: {eval_row}"
    );
}

// T-270: fn ≥1 (known-FN) を含む corpus でも metrics 計算は完走する (FN で fail しない)。
#[test]
fn known_fn_in_corpus_does_not_fail_metrics() {
    let config = harness_config();
    let samples = [CorpusSample {
        rule: "eval",
        path: "/src/app.ts",
        content: "export const safe = 1;\n",
        expectation: Expectation::Fire,
    }];
    let tallies = tally_corpus(&samples, &config);
    assert_eq!(tallies["eval"].fn_count, 1);
    let report = build_report(
        tallies,
        &BTreeMap::new(),
        BTreeMap::new(),
        OverrideMetrics::default(),
    );
    assert!(report.rules["eval"].recall.abs() < f64::EPSILON);
}

// T-271: 全 corpus sample の median latency (≥50 回、全 rule on + oxlint off) が 10ms 未満。
// 値は per-rule worst として metrics に記録され、snapshot を JSON / stderr に出力する。
#[test]
fn metrics_snapshot_measures_all_samples_under_10ms() {
    let config = harness_config();
    let tallies = tally_corpus(corpus::SAMPLES, &config);

    let mut rule_latency: BTreeMap<String, u64> = BTreeMap::new();
    for sample in corpus::SAMPLES {
        let median = median_latency_us(sample.path, sample.content, &config);
        assert!(
            median < 10_000,
            "sample for rule {} ({:?}) median {median}us exceeds 10ms",
            sample.rule,
            sample.expectation,
        );
        let entry = rule_latency.entry(sample.rule.to_owned()).or_insert(0);
        *entry = (*entry).max(median);
    }

    let override_config = metrics_override_config();
    let override_metrics =
        tally_override_metrics(corpus::SAMPLES, &override_config, |path, content| {
            detected_rules_with_overrides(path, content, override_config.clone())
        });

    let report = build_report(
        tallies,
        &rule_latency,
        toggle_latency_diagnostics(),
        override_metrics,
    );
    emit_metrics(&report);
}

/// `literal_separator(true)` は `compile_override_entry` に合わせる。既定の
/// `*` は `/` をまたぎ、production と別の pattern 意味論になる。
fn override_entry(pattern: &str, rules_json: &str) -> OverrideEntry {
    OverrideEntry {
        files: vec![GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .expect("test pattern compiles")
            .compile_matcher()],
        rules: serde_json::from_str(rules_json).expect("test rules JSON parses"),
    }
}

/// The config the gated snapshot measures the override axis against. The
/// production config carries no `overrides`, so both counters would stay at 0
/// under it whatever override resolution does.
fn metrics_override_config() -> Config {
    let mut config = harness_config();
    config.git_root = Some(PathBuf::from("/"));
    config.overrides = vec![override_entry("src/app.ts", r#"{"eval": false}"#)];
    config
}

/// `detected_rules` alone would ignore `config.overrides`: `collect_violations`
/// never reads them, so the resolution step `run_hook_with_input` performs
/// first has to happen here too. Override notes are discarded; the pipeline
/// notes that must fail loudly are checked inside `detected_rules`.
fn detected_rules_with_overrides(path: &str, content: &str, config: Config) -> BTreeSet<String> {
    let mut override_notes = Vec::new();
    let resolved = super::resolve_effective_rules_with_notes(config, path, &mut override_notes);
    detected_rules(path, content, &resolved)
}

// T-489: override が対象 rule を無効化したパスでは fire サンプルが黙る
#[test]
fn override_が対象_rule_を無効化したパスでは_fire_サンプルが黙る() {
    let sample = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == "eval" && s.expectation == Expectation::Fire)
        .expect("corpus has an eval fire sample");

    let mut config = harness_config();
    config.git_root = Some(PathBuf::from("/"));
    config.overrides = vec![override_entry("src/app.ts", r#"{"eval": false}"#)];

    let detected = detected_rules_with_overrides(sample.path, sample.content, config);
    assert!(
        !detected.contains("eval"),
        "eval must not fire once the matching override disables it; got: {detected:?}"
    );
}

// T-490: override の pattern に一致しないパスでは fire サンプルが発火する
#[test]
fn override_の_pattern_に一致しないパスでは_fire_サンプルが発火する() {
    let sample = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == "eval" && s.expectation == Expectation::Fire)
        .expect("corpus has an eval fire sample");

    let mut config = harness_config();
    config.git_root = Some(PathBuf::from("/"));
    config.overrides = vec![override_entry("src/other.ts", r#"{"eval": false}"#)];

    let detected = detected_rules_with_overrides(sample.path, sample.content, config);
    assert!(
        detected.contains("eval"),
        "eval must still fire when no override pattern matches the path; got: {detected:?}"
    );
}

// T-491: `git_root` を `/` にすると corpus の仮想パスが production と同じ
// root 相対形に正規化される。ネストした path を持つ sample を選ぶのは、
// `app/api/*.ts` が一致するのが正規化された場合に限られるため。
#[test]
fn git_root_を_root_にすると_corpus_の仮想パスが_production_と同じ_root_相対形に正規化される() {
    let sample = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == "child-process-injection" && s.expectation == Expectation::Fire)
        .expect("corpus has a child-process-injection fire sample");

    let mut config = harness_config();
    config.git_root = Some(PathBuf::from("/"));
    config.overrides = vec![override_entry("app/api/*.ts", r#"{"astSecurity": false}"#)];

    let detected = detected_rules_with_overrides(sample.path, sample.content, config);
    assert!(
        !detected.contains("child-process-injection"),
        "child-process-injection must not fire once the root-relative override pattern \
         disables ast_security, proving the virtual path normalized under git_root \"/\"; \
         got: {detected:?}"
    );
}

// 数えるのは Fire サンプルだけ。override は disable 方向にしか効かないので、
// Clean サンプルには計上先がない。`Tally::fn_count` は再利用しない。rule 自体の
// false negative と override の適用漏れは別の失敗モードで、ci.yml は前者を
// 意図的に gate していない。
//
// `leak` (適用漏れ): override が無効化するはずの path で rule が検出された件数。
// `overreach` (過剰適用): override の対象外の path で、base の toggle なら検出
// される rule が検出されなくなった件数。

/// Override-application confusion counts, at the same report hierarchy level
/// as `rules` / `toggle_latency_us` (see `MetricsReport`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideMetrics {
    leak: u32,
    overreach: u32,
}

/// Tallies `leak` / `overreach` over `samples`' Fire entries. `detect` is
/// injected (rather than calling `detected_rules_with_overrides` directly)
/// so a test can swap in `detected_rules` (which never resolves
/// `config.overrides`) to prove the honoring path actually lowers `leak`
/// (T-493).
///
/// "Does an override pattern disable this sample's rule for this path" is
/// answered via `Config::effective_rules_with_notes` + `RulesConfig::
/// disabled_since` — the same production resolution `detected_rules_with_overrides`
/// runs, not a re-derivation — compared against `toggle_isolation_cases()`'s
/// `rule_id` -> toggle-name mapping (reused in reverse) to find which toggle
/// gates `sample.rule`.
fn tally_override_metrics(
    samples: &[CorpusSample],
    config: &Config,
    detect: impl Fn(&str, &str) -> BTreeSet<String>,
) -> OverrideMetrics {
    let toggle_for_rule: BTreeMap<&str, &str> = toggle_isolation_cases()
        .into_iter()
        .flat_map(|(toggle, _config, rules)| rules.iter().map(move |rule| (*rule, toggle)))
        .collect();

    let mut metrics = OverrideMetrics::default();
    for sample in samples {
        if sample.expectation != Expectation::Fire {
            continue;
        }
        let toggle = toggle_for_rule.get(sample.rule).unwrap_or_else(|| {
            panic!(
                "no toggle_isolation_cases() mapping for rule_id {}",
                sample.rule
            )
        });
        let (resolved, _override_notes) = config.effective_rules_with_notes(sample.path);
        let intended_disabled = resolved.disabled_since(&config.rules).contains(toggle);
        let fired = detect(sample.path, sample.content).contains(sample.rule);
        // A sample that stays silent under the base toggles too is a false
        // negative, which `ci.yml` leaves ungated on purpose. Only a sample
        // the base config fires can be silenced by an override reaching too
        // far.
        let baseline_fired =
            detected_rules(sample.path, sample.content, config).contains(sample.rule);
        match (intended_disabled, fired) {
            (true, true) => metrics.leak += 1,
            (false, false) if baseline_fired => metrics.overreach += 1,
            _ => {}
        }
    }
    metrics
}

// T-492: override が効いている状態では適用漏れと過剰適用がどちらも 0 になる
#[test]
fn override_が効いている状態では適用漏れと過剰適用がどちらも_0_になる() {
    let unrelated = corpus::SAMPLES
        .iter()
        .find(|s| s.rule == "hardcoded-secret" && s.expectation == Expectation::Fire)
        .expect("corpus has a hardcoded-secret fire sample");
    let samples = [
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Fire,
        },
        CorpusSample {
            rule: unrelated.rule,
            path: unrelated.path,
            content: unrelated.content,
            expectation: unrelated.expectation,
        },
    ];

    let mut config = harness_config();
    config.git_root = Some(PathBuf::from("/"));
    config.overrides = vec![override_entry("src/app.ts", r#"{"eval": false}"#)];

    let metrics = tally_override_metrics(&samples, &config, |path, content| {
        detected_rules_with_overrides(path, content, config.clone())
    });

    assert_eq!(
        metrics.leak, 0,
        "override が効くパスで fire が漏れてはいけない"
    );
    assert_eq!(
        metrics.overreach, 0,
        "override が効かないパスの fire を沈黙させてはいけない"
    );
}

// T-493: override を無視する実装に差し替えると適用漏れの件数が増える
#[test]
fn override_を無視する実装に差し替えると適用漏れの件数が増える() {
    let samples = [CorpusSample {
        rule: "eval",
        path: "/src/app.ts",
        content: "eval(userInput);\n",
        expectation: Expectation::Fire,
    }];

    let mut config = harness_config();
    config.git_root = Some(PathBuf::from("/"));
    config.overrides = vec![override_entry("src/app.ts", r#"{"eval": false}"#)];

    let honoring = tally_override_metrics(&samples, &config, |path, content| {
        detected_rules_with_overrides(path, content, config.clone())
    });
    // `detected_rules` calls `collect_violations` directly and never resolves
    // `config.overrides` (see its doc comment above), so plugging it in here
    // stands in for an implementation that dropped override resolution.
    let ignoring = tally_override_metrics(&samples, &config, |path, content| {
        detected_rules(path, content, &config)
    });

    assert_eq!(honoring.leak, 0);
    assert!(
        ignoring.leak > honoring.leak,
        "ignoring overrides must raise the leak count: honoring={honoring:?} ignoring={ignoring:?}"
    );
}

// T-500: gate が回す config は corpus の fire サンプルを 1 件以上 override の
// 対象にする
#[test]
fn gate_の_config_では_corpus_の仮想パスが_override_の_pattern_に一致する() {
    let config = metrics_override_config();

    let matched = corpus::SAMPLES
        .iter()
        .filter(|s| s.expectation == Expectation::Fire)
        .filter(|s| {
            let (resolved, _) = config.effective_rules_with_notes(s.path);
            !resolved.disabled_since(&config.rules).is_empty()
        })
        .count();

    assert!(
        matched > 0,
        "override の対象になる fire サンプルが 1 件も無いと、gate は override 軸を測らない"
    );
}

// T-498: baseline でも黙るサンプルは過剰適用に数えない (false negative との切り分け)
#[test]
fn baseline_でも黙るサンプルは過剰適用に数えない() {
    // どの rule も踏まない content を Fire として宣言したサンプル。override の
    // 対象外なので、素朴な実装では過剰適用に化ける。
    let samples = [CorpusSample {
        rule: "eval",
        path: "/src/untouched.ts",
        content: "const value = 1;\n",
        expectation: Expectation::Fire,
    }];
    let config = metrics_override_config();

    let metrics = tally_override_metrics(&samples, &config, |path, content| {
        detected_rules_with_overrides(path, content, config.clone())
    });

    assert_eq!(
        metrics.overreach, 0,
        "false negative は ci.yml が意図的に gate していない軸なので、ここで拾ってはいけない"
    );
}

// T-499: gate の fixture が MetricsReport の schema からずれると落ちる
#[test]
fn gate_の_fixture_は_metricsreport_の_schema_と一致する() {
    // fixture は数値シナリオを表すので手書きのまま置く。schema が動いたときだけ
    // 落ちればよく、`deny_unknown_fields` 付きの deserialize がその判定になる。
    for relative in [
        "scripts/fixtures/precision_gate/bootstrap/head.json",
        "scripts/fixtures/precision_gate/fail/base.json",
        "scripts/fixtures/precision_gate/fail/head.json",
    ] {
        let raw = read_fixture(relative);
        serde_json::from_str::<MetricsReport>(&raw)
            .unwrap_or_else(|e| panic!("{relative} must match the MetricsReport schema: {e}"));
    }

    // bootstrap の base は override 軸が入る前の形を表すので、軸を足したときに
    // 初めて schema と一致する。
    let raw = read_fixture("scripts/fixtures/precision_gate/bootstrap/base.json");
    assert!(
        serde_json::from_str::<MetricsReport>(&raw).is_err(),
        "bootstrap の base は override 軸を持たない形でなければ意味を失う"
    );
    let with_axis = raw.trim_end().trim_end_matches('}').to_owned()
        + r#", "overrides": {"leak": 0, "overreach": 0} }"#;
    serde_json::from_str::<MetricsReport>(&with_axis)
        .unwrap_or_else(|e| panic!("bootstrap base must match the schema minus the axis: {e}"));
}

fn read_fixture(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

// T-494: 既存の `rules` 軸の値が override 軸の追加で変わらない
#[test]
fn 既存の_rules_軸の値が_override_軸の追加で変わらない() {
    let config = harness_config();
    let samples = [
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Fire,
        },
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Clean,
        },
    ];
    let tallies = tally_corpus(&samples, &config);

    let override_metrics = OverrideMetrics {
        leak: 2,
        overreach: 3,
    };
    let report = build_report(tallies, &BTreeMap::new(), BTreeMap::new(), override_metrics);

    let eval = &report.rules["eval"];
    assert_eq!(eval.tp, 1);
    assert_eq!(eval.fp, 1);
    assert_eq!(eval.fn_count, 0);
    assert!((eval.precision - 0.5).abs() < f64::EPSILON);
    assert!((eval.recall - 1.0).abs() < f64::EPSILON);
}

// `write_metrics_json` を直接呼ばず `emit_metrics` (env var 分岐) を経由する。
// ci.yml が叩くのと同じ経路を通さないと、env var 分岐自体の回帰を拾えない。

/// `emit_metrics` は process 全体の環境変数を読むため、cargo test の並列実行下で
/// 複数 test が同時に `GUARDRAILS_METRICS_OUT` を書き換えると競合する。この Mutex は
/// T-495..T-497 の 3 test 間でのみ、その書き換え区間を直列化する。
static METRICS_ENV_LOCK: Mutex<()> = Mutex::new(());

fn precision_gate_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/precision_gate.sh")
}

/// `emit_metrics` の `GUARDRAILS_METRICS_OUT` 分岐を経由して `report` を `path` に書き出す。
fn write_via_metrics_out_env(report: &MetricsReport, path: &Path) {
    let _guard = METRICS_ENV_LOCK.lock().unwrap();
    env::set_var("GUARDRAILS_METRICS_OUT", path);
    emit_metrics(report);
    env::remove_var("GUARDRAILS_METRICS_OUT");
}

/// `scripts/precision_gate.sh <base> <head>` を実行し、gate の終了コードが
/// 成功 (exit 0) だったかを返す。
fn run_gate(base: &Path, head: &Path) -> bool {
    Command::new(precision_gate_script())
        .arg(base)
        .arg(head)
        .output()
        .expect("spawn scripts/precision_gate.sh")
        .status
        .success()
}

fn tiny_report(overrides: OverrideMetrics) -> MetricsReport {
    let config = harness_config();
    let samples = [
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "eval(userInput);\n",
            expectation: Expectation::Fire,
        },
        CorpusSample {
            rule: "eval",
            path: "/src/app.ts",
            content: "export const x = 1;\n",
            expectation: Expectation::Clean,
        },
    ];
    let tallies = tally_corpus(&samples, &config);
    build_report(tallies, &BTreeMap::new(), BTreeMap::new(), overrides)
}

// T-495: 書き出した JSON を head 側に、同じ JSON を base 側に渡すと gate は成功で返る
#[test]
fn 書き出した_json_を_head_側に_同じ_json_を_base_側に渡すと_gate_は成功で返る() {
    let report = tiny_report(OverrideMetrics::default());

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("metrics.json");
    write_via_metrics_out_env(&report, &path);

    assert!(
        run_gate(&path, &path),
        "same JSON as both base and head must pass the gate"
    );
}

// T-496: 適用漏れを 1 件増やした JSON を head 側に渡すと gate は失敗で返る
#[test]
fn 適用漏れを_1_件増やした_json_を_head_側に渡すと_gate_は失敗で返る() {
    let base_report = tiny_report(OverrideMetrics {
        leak: 0,
        overreach: 0,
    });
    let head_report = tiny_report(OverrideMetrics {
        leak: 1,
        overreach: 0,
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let base_path = dir.path().join("base.json");
    let head_path = dir.path().join("head.json");
    write_via_metrics_out_env(&base_report, &base_path);
    write_via_metrics_out_env(&head_report, &head_path);

    assert!(
        !run_gate(&base_path, &head_path),
        "leak increasing by one on head must fail the gate"
    );
}

// T-497: override 軸を持たない JSON を base 側に渡すと gate は bootstrap として成功で返る
#[test]
fn override_軸を持たない_json_を_base_側に渡すと_gate_は_bootstrap_として成功で返る() {
    let report = tiny_report(OverrideMetrics::default());

    let dir = tempfile::tempdir().expect("tempdir");
    let base_path = dir.path().join("base.json");
    let head_path = dir.path().join("head.json");
    write_via_metrics_out_env(&report, &base_path);
    write_via_metrics_out_env(&report, &head_path);

    // U-002 (override 軸) 導入前の base.json を模す: 手書き JSON で schema を
    // 別に定義するのではなく、実際に production の env var 経路で書き出した
    // JSON から "overrides" キーを取り除く。schema が実物からずれない。
    let mut base_value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&base_path).expect("read base"))
            .expect("parse base json");
    base_value
        .as_object_mut()
        .expect("report serializes as a JSON object")
        .remove("overrides");
    fs::write(
        &base_path,
        serde_json::to_string_pretty(&base_value).expect("serialize stripped base"),
    )
    .expect("write stripped base");

    assert!(
        run_gate(&base_path, &head_path),
        "base predating the override axis must bootstrap-skip, not fail"
    );
}
