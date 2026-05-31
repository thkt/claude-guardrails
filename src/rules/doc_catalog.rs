//! Test-only single source for the README rule tables (Issue #257).
//!
//! `data::RULE_DOCS` is the authoritative content for the `### Rules` /
//! `### Security Rules` / `### AST Security Rules` tables in both `README.md`
//! and `README.ja.md`. Each table is wrapped in `<!-- BEGIN/END GENERATED: ...
//! -->` markers; [`readme_rule_tables_match_catalog`] fails when a committed
//! README drifts from `RULE_DOCS`, and [`rule_docs_cover_catalog`] fails when a
//! `rule_id` gains or loses a documented row (the drift that recurred in
//! Issue #98 and Issue #156).
//!
//! After editing `RULE_DOCS`, regenerate both READMEs with:
//!
//! ```text
//! cargo test bless_readme_rule_tables -- --ignored
//! ```

use super::rule_id;
use std::collections::HashSet;
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

const TABLES: [Table; 3] = [Table::Rules, Table::Security, Table::AstSecurity];
const LANGS: [Lang; 2] = [Lang::En, Lang::Ja];

fn marker_name(table: Table) -> &'static str {
    match table {
        Table::Rules => "rules-table",
        Table::Security => "security-rules-table",
        Table::AstSecurity => "ast-security-rules-table",
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
    }
}

fn separator(table: Table) -> &'static str {
    match table {
        Table::Rules => "| --- | --- | --- | --- | --- |",
        Table::Security | Table::AstSecurity => "| --- | --- | --- | --- |",
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
