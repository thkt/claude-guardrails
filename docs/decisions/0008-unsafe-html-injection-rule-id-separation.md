---
status: "accepted"
date: 2026-05-14
decision-makers: thkt
---

# ast_security 配下の innerHTML / document.write を unsafe-html-injection に分離

## Context and Problem Statement

`rule_id::SECURITY` ("security") が 2 つの異なる toggle 配下で同一 ID として発火している。

| 発火元                                                            | toggle              | 検出対象                                                                                          |
| ----------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------- |
| `src/rules/security.rs` の `SECURITY_ISSUES`                      | `config.rules.security`     | `setTimeout('str')` / `setInterval('str')` / `postMessage(_, '*')` / sensitive `localStorage` / sensitive `sessionStorage` |
| `src/ast_security.rs` の `check_html_assignment` / `check_document_write` | `config.rules.ast_security` | `innerHTML = nonliteral` / `outerHTML = nonliteral` / `document.write[ln](nonliteral)`            |

JSON envelope の violation を rule で振り分ける consumer (CI 集計 / dashboard / ignore-list) からは両者を区別できない。一方で toggle は分離しているため、`security: false` でも innerHTML 検出は残り、`astSecurity: false` でも setTimeout 検出は残る。この toggle と ID の対応のズレが BREAKING を伴わない部分的な無効化を不可能にしている。

## Decision Drivers

* JSON envelope rule field の意味的一貫性 (1 rule_id ↔ 1 toggle)
* consumer (CI / Claude Code エージェント) が rule_id で確実に振り分けられること
* ADR-0003 で確立した「用法確定性」軸との整合 (高確度な構文検出 = High)
* BREAKING の規模を最小化 (security.rs 側は触らない)

## Considered Options

* ast_security 側の SECURITY 発火を新 rule_id `unsafe-html-injection` に分離 (採用)
* ast_security 側の SECURITY 発火を 3 つの細粒度 ID (`unsafe-inner-html` / `unsafe-outer-html` / `document-write-injection`) に分離
* ID は維持したまま toggle を `astSecurity` から `security` に移動して統一
* 現状維持 + README に注記

## Decision Outcome

採用: ast_security の `check_html_assignment` / `check_document_write` が発火する rule_id を `SECURITY` → `UNSAFE_HTML_INJECTION` (`"unsafe-html-injection"`) に分離する。

| 発火元 関数                          | 対象                                  | Severity (ADR-0003 用法確定性) |
| ------------------------------------ | ------------------------------------- | ------------------------------ |
| `check_html_assignment` (innerHTML)  | `el.innerHTML = nonliteral`           | High (HTML 解釈 sink、確定)    |
| `check_html_assignment` (outerHTML)  | `el.outerHTML = nonliteral`           | Medium (副作用が要素置換に限定) |
| `check_document_write`               | `document.write[ln](nonliteral)`      | High (HTML 解釈 sink、確定)    |

`src/rules/security.rs` の SECURITY_ISSUES (setTimeout/setInterval/postMessage/storage 系) はそのまま `rule_id::SECURITY` を発火する。`config.rules.security` toggle 配下のまま維持。

### Consequences

* Good, JSON envelope の `rule` field と toggle が 1:1 対応する。consumer から見た契約が単純化
* Good, `astSecurity: false` で innerHTML 検出を切ったときに `security` 検出が残る (逆も同じ) — toggle の意味が明確
* Good, ADR-0003 と同じ用法確定性軸で severity を再評価できた
* Bad, JSON output の `rule` field が変わる BREAKING。`"rule": "security"` で innerHTML/document.write を振り分けていた consumer は新 ID `"unsafe-html-injection"` に追従する必要
* Bad, ast_security 側のテスト 9 件 (T-019 / T-020 / T-021 系) の assertion を更新

### Confirmation

実装後に `cargo test` で T-019 / T-020 / T-021 系の assertion が新 rule_id を要求することを確認。README.md / README.ja.md の AST Security Rules テーブルに `unsafe-html-injection` 行を追加し、rule_id の意味が文書上も独立していることを示す。

## Pros and Cons of the Options

### ast_security 側を `unsafe-html-injection` に分離

* Good, BREAKING を 1 ID 増設で抑える
* Good, 「HTML を直接 DOM に流し込む sink」というカテゴリで自然
* Bad, JSON output BREAKING

### 3 つの細粒度 ID に分離

* Good, innerHTML / outerHTML / document.write を個別に enable/disable したい consumer に有利
* Bad, rule_id が増えすぎて Custom Rules テーブルが肥大、現状 call site が観測できない (YAGNI)

### toggle を `security` に移動して統一

* Good, ID 変更なしで toggle と ID の対応が揃う
* Bad, AST 解析を `security` toggle 配下に置くと、line-based security ルールだけ切りたいユーザーが AST 解析も巻き込まれる (現状と逆方向の制約)

### 現状維持 + README 注記

* Good, BREAKING 回避
* Bad, OUTCOME B1 ("AI エージェント が同サイクルで修正") の前提となる「rule_id で振り分け可能」が成立しない

## More Information

### Quality Attributes

| Attribute        | Priority | Approach                                            |
| ---------------- | -------- | --------------------------------------------------- |
| 契約の単純さ     | High     | rule_id と toggle を 1:1 対応                       |
| BREAKING 最小化  | Medium   | ast_security 側のみ変更、security.rs は据え置き     |
| 命名の汎用性     | Medium   | `unsafe-html-injection` で 3 種類 sink を内包       |

### Trade-offs

下位互換性を犠牲にして、JSON envelope の契約の意味的一貫性を得る。

### Reassessment Triggers

* `unsafe-html-injection` が他の HTML sink (Range.createContextualFragment 等) の拡張で抽象度が崩れた場合、3 つの細粒度 ID への再分離を検討
* `define_rule_config!` macro が rule_id 単位の toggle を受けるよう拡張された場合、toggle 粒度を rule_id と揃える方向を再検討
