---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# reporter stderr の `━` 装飾と anti-circumvention 文言を維持する

## Context and Problem Statement

`src/io/reporter.rs` の `format_violations` が hook stderr に出力する 2 つの装飾要素について、design intent が ADR で記録されていないため「意図的設計」か「token 浪費 / 過剰表現」かを後から判別できない状態にあった。

| 要素                    | 出力                                                 | 長さ                    |
| ----------------------- | ---------------------------------------------------- | ----------------------- |
| `━` ボーダー            | `Guardrails ━━━...` (39 chars) + `━━━...` (50 chars) | 計 89 chars / hook 起動 |
| anti-circumvention 文言 | `Do not circumvent this check.`                      | 29 chars / blocking 時  |

Issue #127 で両要素の design intent を確認し、結論を本 ADR に固定する。

## Decision Drivers

- AI agent の編集サイクル内でフィードバックが視認しやすい (OUTCOME: hook の stderr の指示を読み、人手介入なしで修正を完了する)
- hook の出力を debug する人間 (運用者・開発者) も同時に読みやすい
- LLM が hook 違反を「修正対象」ではなく「迂回対象」として扱う傾向を抑止する
- 装飾削減による token 節約と、上記要件のトレードオフを明示する

## Considered Options

### S1: `━` ボーダー装飾

- **A. 現状維持 (採用)**: 89 chars の borders を維持し、`Guardrails` ヘッダーとフッターを視覚分離する
- B. 削除: `✗` 記号 + 空行で代替し、token を節約する

### S2: anti-circumvention 文言

- **C. 現状維持 (採用)**: `BLOCKED: ... Do not circumvent this check.` を維持する
- D. 中立文言に置換: `Fix these to proceed.` 等で「敵対的トーン」を回避する

## Decision Outcome

### S1 → Option A (現状維持)

dual-audience (AI + 人間) を前提とする。AI agent の編集サイクルでフィードバックを読む主体は AI だが、hook output を debug / 監視する人間も同時に視認する場面が存在する。`━` ボーダーはブロックされた範囲を画面上で識別するための視覚分離として機能する。

### S2 → Option C (現状維持)

commit `0103129` で確立された design intent をそのまま維持する:

> LLMs treat hook errors as obstacles to bypass (modifying lint config, writing via Bash, etc.) rather than feedback to fix code. Adding an explicit "do not circumvent" instruction to the BLOCKED footer guides the LLM toward fixing the source code instead.

「コードを修正せよ」を明示する anti-circumvention 文言は jailbreak/bypass 抑止として機能する。中立文言に置換すると LLM が config 改変や Bash 経由書き込みなどの迂回経路を選ぶ確率が上がる懸念がある。

### Scope

本 ADR は `src/io/reporter.rs` の以下 2 箇所の現状維持を固定する:

- `HEADER_SEPARATOR` / `FOOTER_SEPARATOR` (border 装飾)
- `BLOCKED: Fix N issue(s) in the source code and retry. Do not circumvent this check.` (anti-circumvention 文言)

`format_warnings` 側 (`⚠` warning) の装飾、severity 表示順序、rule 名表示形式は本 ADR の対象外。

### Consequences

- Good: AI agent と人間の dual-audience を両立する出力フォーマットを意図的に維持する根拠が残る
- Good: jailbreak/bypass 抑止文言の意図が ADR で記録され、後続の reviewer が「敵対的トーン」として誤って削除することを防げる
- Good: 既存 reporter test (`format_violations_single_issue` で `"━"` と `"BLOCKED"` を assert) が現状文言を固定済みで、回帰検出が機能する
- Bad: blocking 時に 1 hook 起動あたり 89 chars (border) + 29 chars (anti-circumvention) ≈ 118 chars の token を AI context に追加する。dual-audience と jailbreak 抑止の要件に対する許容コスト
- Bad: 将来 AI-only 利用が標準化したとき、本 ADR は Superseded として更新が必要

### Verification

- `src/io/reporter.rs` の `format_violations_single_issue` で `output.contains("━")` と `output.contains("BLOCKED")` を assert 済み
- `format_violations` 本体に `BLOCKED:` 文言と `Do not circumvent this check.` の連結が残っていることは grep で固定可能
