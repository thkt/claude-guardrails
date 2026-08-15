//! Test-only single source for the README rule tables (Issue #257).
//!
//! `data::RULE_DOCS` is the authoritative content for the `### Rules` /
//! `### Security Rules` / `### AST Security Rules` tables in both `README.md`
//! and `README.ja.md`. Each table is wrapped in `<!-- BEGIN/END GENERATED: ...
//! -->` markers; [`readme_rule_tables_match_catalog`] fails when a committed
//! README drifts from `RULE_DOCS`, and [`rule_docs_cover_catalog`] fails when a
//! `rule_id` gains or loses a documented row (the drift that recurred in
//! Issue #98 and Issue #156). [`readme_config_example_lists_all_toggles`] fails
//! when the default config example's `rules` block stops enumerating exactly the
//! toggle set (Issue #260, the third drift face of Issue #156 F-011).
//! [`config_toggles_match_rule_docs`] fails when `define_rule_config!`'s public
//! toggle set (minus the deprecated `biome`) drifts from the documented `Rules`
//! toggles — catching a `rule_id`-less umbrella toggle added to the config
//! contract without a matching `RULE_DOCS` row, which would otherwise slip every
//! other gate here.
//!
//! After editing `RULE_DOCS`, regenerate both READMEs with:
//!
//! ```text
//! cargo test bless_readme_rule_tables -- --ignored
//! ```

use super::rule_id;
use crate::config::RULE_TOGGLE_NAMES;
use std::collections::{BTreeSet, HashSet};
use std::fs;

mod data;

/// Which README table a [`RuleDoc`] belongs to. Column shape differs per table.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Table {
    /// `### Rules` — toggle-level, 5 columns including `When to disable`.
    Rules,
    /// `### Security Rules (`security`)` — rule_id-level, 4 columns.
    Security,
    /// `### AST Security Rules (`astSecurity`)` — rule_id-level, 4 columns.
    AstSecurity,
    /// `### Invariant Rules (`invariant`)` — rule_id-level, 4 columns.
    Invariant,
}

/// README language. `severity` and `key` are shared; prose differs per language
/// (the JA README is a separate human translation, not a literal mirror).
#[derive(Clone, Copy)]
enum Lang {
    En,
    Ja,
}

/// One documented row in both languages. `rule_id` is `None` for aggregate
/// `Rules` rows (`security`, `astSecurity`) whose sub-rules are documented in
/// their own table; every other row names the `rule_id` it documents, which
/// ties the catalog to [`rule_id::RULE_ID_CATALOG`] via [`rule_docs_cover_catalog`].
struct RuleDoc {
    table: Table,
    /// First-column label, without the surrounding backticks. Language-neutral.
    key: &'static str,
    rule_id: Option<&'static str>,
    /// Documentation severity string (`"Mixed"` etc.); shared by both languages
    /// and distinct from the runtime per-violation [`super::Severity`] enum.
    severity: &'static str,
    description: &'static str,
    why: &'static str,
    /// `Some` only for [`Table::Rules`] (the only 5-column table).
    when_to_disable: Option<&'static str>,
    description_ja: &'static str,
    why_ja: &'static str,
    when_to_disable_ja: Option<&'static str>,
}

const TABLES: [Table; 4] = [
    Table::Rules,
    Table::Security,
    Table::AstSecurity,
    Table::Invariant,
];
const LANGS: [Lang; 2] = [Lang::En, Lang::Ja];

fn marker_name(table: Table) -> &'static str {
    match table {
        Table::Rules => "rules-table",
        Table::Security => "security-rules-table",
        Table::AstSecurity => "ast-security-rules-table",
        Table::Invariant => "invariant-rules-table",
    }
}

fn readme_path(lang: Lang) -> &'static str {
    match lang {
        Lang::En => concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"),
        Lang::Ja => concat!(env!("CARGO_MANIFEST_DIR"), "/README.ja.md"),
    }
}

/// Section heading that anchors each table during bootstrap (markers absent).
/// Prefix-only for the parenthesized headings so it survives backtick edits.
fn heading(table: Table, lang: Lang) -> &'static str {
    match (lang, table) {
        (Lang::En, Table::Rules) => "\n### Rules\n",
        (Lang::En, Table::Security) => "\n### Security Rules (",
        (Lang::En, Table::AstSecurity) => "\n### AST Security Rules (",
        (Lang::Ja, Table::Rules) => "\n### ルール\n",
        (Lang::Ja, Table::Security) => "\n### セキュリティルール（",
        (Lang::Ja, Table::AstSecurity) => "\n### ASTセキュリティルール（",
        (Lang::En, Table::Invariant) => "\n### Invariant Rules (",
        (Lang::Ja, Table::Invariant) => "\n### 不変値ルール（",
    }
}

fn header(table: Table, lang: Lang) -> &'static str {
    match (lang, table) {
        (Lang::En, Table::Rules) => {
            "| Rule | Severity | Description | Why it matters | When to disable |"
        }
        (Lang::En, Table::Security) => {
            "| Sub-rule (rule_id) | Severity | Description | Why it matters |"
        }
        (Lang::En, Table::AstSecurity) => "| Sub-rule | Severity | Description | Why it matters |",
        (Lang::Ja, Table::Rules) => "| ルール | 重大度 | 説明 | なぜ重要か | 無効化する場面 |",
        (Lang::Ja, Table::Security) => "| サブルール (rule_id) | 重大度 | 説明 | なぜ重要か |",
        (Lang::Ja, Table::AstSecurity) => "| サブルール | 重大度 | 説明 | なぜ重要か |",
        (Lang::En, Table::Invariant) => {
            "| Sub-rule (rule_id) | Severity | Description | Why it matters |"
        }
        (Lang::Ja, Table::Invariant) => "| サブルール (rule_id) | 重大度 | 説明 | なぜ重要か |",
    }
}

fn separator(table: Table) -> &'static str {
    match table {
        Table::Rules => "| --- | --- | --- | --- | --- |",
        Table::Security | Table::AstSecurity | Table::Invariant => "| --- | --- | --- | --- |",
    }
}

/// Picks the (description, why, `when_to_disable`) triple for `lang`.
fn cells(doc: &RuleDoc, lang: Lang) -> (&'static str, &'static str, Option<&'static str>) {
    match lang {
        Lang::En => (doc.description, doc.why, doc.when_to_disable),
        Lang::Ja => (doc.description_ja, doc.why_ja, doc.when_to_disable_ja),
    }
}

fn render_row(doc: &RuleDoc, lang: Lang) -> String {
    let key = format!("`{}`", doc.key);
    let (description, why, when_to_disable) = cells(doc, lang);
    match when_to_disable {
        Some(wtd) => format!(
            "| {key} | {} | {description} | {why} | {wtd} |",
            doc.severity
        ),
        None => format!("| {key} | {} | {description} | {why} |", doc.severity),
    }
}

/// Renders one table's marker body for `lang`: header, separator, then rows in
/// `RULE_DOCS` declaration order (which is the README row order).
fn render_table(table: Table, lang: Lang) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(header(table, lang));
    out.push('\n');
    out.push_str(separator(table));
    for doc in data::RULE_DOCS.iter().filter(|d| d.table == table) {
        out.push('\n');
        out.push_str(&render_row(doc, lang));
    }
    out
}

/// Byte range between a `name` marker pair, or `None` when the BEGIN marker is
/// absent (the bless bootstrap signal). Panics if BEGIN is present but END is
/// missing — a half-marked region is never valid. The sole reader of the marker
/// format strings.
fn try_marked_bounds(readme: &str, name: &str) -> Option<(usize, usize)> {
    let begin = format!("<!-- BEGIN GENERATED: {name} -->");
    let start = readme.find(&begin)? + begin.len();
    let end = format!("<!-- END GENERATED: {name} -->");
    let end_at = readme[start..]
        .find(&end)
        .unwrap_or_else(|| panic!("README missing marker: {end}"))
        + start;
    Some((start, end_at))
}

/// Byte range between a marker pair, panicking if the BEGIN marker is absent.
fn marked_bounds(readme: &str, name: &str) -> (usize, usize) {
    try_marked_bounds(readme, name)
        .unwrap_or_else(|| panic!("README missing marker: <!-- BEGIN GENERATED: {name} -->"))
}

// T-257: rule_docs_cover_catalog
#[test]
fn rule_docs_cover_catalog() {
    let documented: HashSet<&str> = data::RULE_DOCS.iter().filter_map(|d| d.rule_id).collect();
    let catalog: HashSet<&str> = rule_id::RULE_ID_CATALOG.iter().copied().collect();

    let missing: Vec<&str> = catalog.difference(&documented).copied().collect();
    let extra: Vec<&str> = documented.difference(&catalog).copied().collect();

    assert!(
        missing.is_empty(),
        "rule_id 実装済みだが README ルール表に未掲載: {missing:?} (doc_catalog::data::RULE_DOCS に行を追加)"
    );
    assert!(
        extra.is_empty(),
        "README ルール表にあるが rule_id カタログに無い: {extra:?} (RULE_DOCS の rule_id を修正)"
    );
}

// T-258: when_to_disable_matches_table
#[test]
fn when_to_disable_matches_table() {
    for doc in data::RULE_DOCS {
        let in_rules = doc.table == Table::Rules;
        assert_eq!(
            doc.when_to_disable.is_some(),
            in_rules,
            "{} の when_to_disable は Rules 表でのみ Some にする",
            doc.key
        );
        assert_eq!(
            doc.when_to_disable_ja.is_some(),
            in_rules,
            "{} の when_to_disable_ja は Rules 表でのみ Some にする",
            doc.key
        );
    }
}

// T-259: readme_rule_tables_match_catalog
#[test]
fn readme_rule_tables_match_catalog() {
    for lang in LANGS {
        let path = readme_path(lang);
        let readme = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        for table in TABLES {
            let name = marker_name(table);
            let (start, end) = marked_bounds(&readme, name);
            let got = readme[start..end].trim();
            let want = render_table(table, lang);
            assert_eq!(
                got, want,
                "{path} の `{name}` 区間が RULE_DOCS とドリフト。`cargo test bless_readme_rule_tables -- --ignored` で再生成"
            );
        }
    }
}

/// Heading that anchors the default config example (the full-toggle `rules`
/// block) in each README. Anchoring on the heading keeps the partial-override
/// examples under later headings (`### Examples` etc.) out of the parsed region.
fn config_example_heading(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "\n### Schema\n",
        Lang::Ja => "\n### スキーマ\n",
    }
}

/// Body of the default config example: the first fenced code block after the
/// schema heading, with the language tag skipped (so a json to jsonc retag still
/// resolves this block instead of drifting to a later fence). The block body must
/// stay strict JSON. `serde_json` rejects jsonc comments and trailing commas, so
/// only the fence tag may differ. Returns a borrowed slice so callers parse
/// without allocating. Panics if the heading or block is absent (a fixed part of
/// both READMEs).
fn schema_config_json(readme: &str, lang: Lang) -> &str {
    let head = config_example_heading(lang);
    let after_head = readme
        .find(head)
        .unwrap_or_else(|| panic!("README missing heading: {head:?}"))
        + head.len();
    let rel_fence = readme[after_head..]
        .find("```")
        .unwrap_or_else(|| panic!("README has no fenced block after heading: {head:?}"));
    let tag_line = after_head + rel_fence + "```".len();
    let body_start = tag_line
        + readme[tag_line..]
            .find('\n')
            .unwrap_or_else(|| panic!("README fence not terminated after heading: {head:?}"))
        + 1;
    let rel_close = readme[body_start..]
        .find("\n```")
        .unwrap_or_else(|| panic!("README fenced block not closed after heading: {head:?}"));
    &readme[body_start..body_start + rel_close]
}

/// Toggle set the default config example must enumerate: every [`Table::Rules`]
/// key plus `oxlint` (the external-linter toggle, which has no [`RuleDoc`] row).
/// The single source for both READMEs (Issue #260).
fn expected_config_toggles() -> BTreeSet<String> {
    let mut set: BTreeSet<String> = data::RULE_DOCS
        .iter()
        .filter(|d| d.table == Table::Rules)
        .map(|d| d.key.to_owned())
        .collect();
    set.insert("oxlint".to_owned());
    set
}

/// Toggles the config contract declares, minus the deprecated `biome` (warned-on
/// and ignored by `Config::merge`, so intentionally absent from `RULE_DOCS` and the
/// README default). Every remaining toggle is matched by [`expected_config_toggles`]
/// as either a `Table::Rules` row or the `oxlint` external-linter toggle it inserts
/// manually (no `RuleDoc` row). The single source is `define_rule_config!`.
fn config_contract_toggles() -> BTreeSet<String> {
    RULE_TOGGLE_NAMES
        .iter()
        // biome: deprecated, warned + ignored in Config::merge, not a documented toggle
        .filter(|&&name| name != "biome")
        .map(|&name| name.to_owned())
        .collect()
}

/// Bidirectional drift between the config contract and the documented toggle set.
/// `missing` = in the contract but absent from the docs (a toggle added to
/// `define_rule_config!` without a `RULE_DOCS` row); `extra` = documented but not in
/// the contract. Pure over its inputs so [`config_toggles_gate_detects_planted_drift`]
/// can feed synthetic sets and prove the gate fires, rather than only confirming the
/// current state matches.
fn toggles_diff<'a>(
    contract: &'a BTreeSet<String>,
    documented: &'a BTreeSet<String>,
) -> (Vec<&'a String>, Vec<&'a String>) {
    (
        contract.difference(documented).collect(),
        documented.difference(contract).collect(),
    )
}

/// Toggle keys in `readme`'s default config example for `lang`. Takes the README
/// text (not a path) so a negative test can feed a synthetic document with
/// planted drift through the same anchor and parse path the gate uses on the
/// committed READMEs.
fn config_example_toggles(readme: &str, lang: Lang) -> BTreeSet<String> {
    let json = schema_config_json(readme, lang);
    let parsed: serde_json::Value =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("schema json parse: {e}"));
    let rules = parsed
        .get("rules")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("schema example missing `rules` object"));
    rules.keys().cloned().collect()
}

// T-260: readme_config_example_lists_all_toggles
#[test]
fn readme_config_example_lists_all_toggles() {
    let expected = expected_config_toggles();
    for lang in LANGS {
        let path = readme_path(lang);
        let readme = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let actual = config_example_toggles(&readme, lang);
        let missing: Vec<&String> = expected.difference(&actual).collect();
        let extra: Vec<&String> = actual.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{path} の config 例 `rules` が toggle 集合とドリフト。未掲載={missing:?} 余分={extra:?} (single source: RULE_DOCS の Table::Rules ∪ oxlint)"
        );
    }
}

// T-261: config_example_gate_detects_planted_drift
#[test]
fn config_example_gate_detects_planted_drift() {
    // Synthetic README whose example drops most toggles and adds a bogus one.
    // The gate (same anchor + parse + diff path as T-260) must flag both
    // directions; a positive-only test stays green here and proves nothing.
    let synthetic =
        "\n### Schema\n\n```json\n{ \"rules\": { \"oxlint\": true, \"sensitiveFile\": true, \"notARealToggle\": true } }\n```\n";
    let expected = expected_config_toggles();
    let actual = config_example_toggles(synthetic, Lang::En);
    let missing: Vec<&String> = expected.difference(&actual).collect();
    let extra: Vec<&String> = actual.difference(&expected).collect();
    assert!(
        missing.iter().any(|s| s.as_str() == "cryptoWeak"),
        "dropped toggle must surface as missing, got missing={missing:?}"
    );
    assert!(
        extra.iter().any(|s| s.as_str() == "notARealToggle"),
        "unknown toggle must surface as extra, got extra={extra:?}"
    );
}

// T-262: config_example_anchor_ignores_fence_language_tag
#[test]
fn config_example_anchor_ignores_fence_language_tag() {
    // The first fence after the heading wins regardless of its language tag: a
    // jsonc-tagged default block resolves, and a later json fence is not selected
    // (finding fence-tag-retag-misdirects). Mirrors the production README's
    // multi-fence layout under the schema heading.
    let synthetic = "\n### Schema\n\n```jsonc\n{ \"rules\": { \"oxlint\": true } }\n```\n\n```json\n{ \"rules\": { \"naming\": true } }\n```\n";
    let toggles = config_example_toggles(synthetic, Lang::En);
    assert!(
        toggles.contains("oxlint"),
        "tag-agnostic anchor must read the first (jsonc) block, got {toggles:?}"
    );
    assert!(
        !toggles.contains("naming"),
        "anchor must not drift to the later json fence, got {toggles:?}"
    );
}

// T-263: config_toggles_match_rule_docs
#[test]
fn config_toggles_match_rule_docs() {
    let contract = config_contract_toggles();
    let documented = expected_config_toggles();
    let (missing, extra) = toggles_diff(&contract, &documented);
    assert!(
        missing.is_empty() && extra.is_empty(),
        "config.rs の toggle 契約と RULE_DOCS がドリフト。RULE_DOCS 未掲載={missing:?} config 未定義={extra:?} (single source: define_rule_config! の serde 名 − biome)"
    );
}

// T-264: config_toggles_gate_detects_planted_drift
#[test]
fn config_toggles_gate_detects_planted_drift() {
    // 合成 contract（実 toggle を全て落とし架空 toggle を 1 つ混入）で両方向の drift が
    // surface することを確認。positive のみでは && の取り違えや difference の方向誤りを
    // 捕まえられない（T-261 が T-260 に対して持つ negative の対）。
    let planted: BTreeSet<String> = ["notARealToggle".to_owned()].into_iter().collect();
    let documented = expected_config_toggles();
    let (missing, extra) = toggles_diff(&planted, &documented);
    assert!(
        missing.iter().any(|s| s.as_str() == "notARealToggle"),
        "contract のみの toggle は missing に出る必要がある: {missing:?}"
    );
    assert!(
        extra.iter().any(|s| s.as_str() == "sensitiveFile"),
        "documented のみの toggle は extra に出る必要がある: {extra:?}"
    );
}

// T-265: config_contract_excludes_deprecated_biome
#[test]
fn config_contract_excludes_deprecated_biome() {
    // biome 除外フィルタの pin。biome の serde 名 rename やフィルタ破損を、T-263 の
    // drift メッセージ経由でなく除外契約そのものとして直接捕捉する。
    let contract = config_contract_toggles();
    assert!(
        !contract.contains("biome"),
        "deprecated 'biome' は contract から除外される必要がある: {contract:?}"
    );
}

/// Region to (re)generate for `table` in `lang`: the bytes between an existing
/// marker pair (`marked = true`), or — before markers exist — the bare table
/// block (its first `|` line through the blank line after its last row), which
/// bless then wraps in markers (`marked = false`). The bootstrap anchors on the
/// section heading, not the header row, because README headers carry alignment
/// padding that the canonical [`header`] output does not reproduce.
fn bless_region(readme: &str, table: Table, lang: Lang) -> (usize, usize, bool) {
    if let Some((start, end)) = try_marked_bounds(readme, marker_name(table)) {
        return (start, end, true);
    }
    let head = heading(table, lang);
    let after_head = readme
        .find(head)
        .unwrap_or_else(|| panic!("README missing heading: {head:?}"))
        + head.len();
    let rel_row = readme[after_head..]
        .find("\n| ")
        .unwrap_or_else(|| panic!("README has no table after heading: {head:?}"));
    let start = after_head + rel_row + 1;
    let end_at = readme[start..]
        .find("\n\n")
        .map_or(readme.len(), |rel| start + rel);
    (start, end_at, false)
}

// Regenerates the marker regions of both READMEs from RULE_DOCS. Ignored so it
// never runs in CI (it writes source files); run explicitly to bless changes.
// Inserts the markers on first run (bootstrap), then replaces between them.
#[test]
#[ignore = "writes README.md / README.ja.md; run explicitly to regenerate the rule tables"]
fn bless_readme_rule_tables() {
    for lang in LANGS {
        let path = readme_path(lang);
        let mut readme = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        for table in TABLES {
            let body = render_table(table, lang);
            let (start, end, marked) = bless_region(&readme, table, lang);
            let replacement = if marked {
                format!("\n{body}\n")
            } else {
                let name = marker_name(table);
                format!("<!-- BEGIN GENERATED: {name} -->\n{body}\n<!-- END GENERATED: {name} -->")
            };
            readme = format!("{}{replacement}{}", &readme[..start], &readme[end..]);
        }
        fs::write(path, readme).unwrap_or_else(|e| panic!("write {path}: {e}"));
    }
}
