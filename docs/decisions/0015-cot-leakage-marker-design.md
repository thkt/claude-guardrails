---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# `cot-leakage-marker` rule の marker 選定 / self-exclusion / Windows path normalize の方針

## Context and Problem Statement

`src/rules/cot_leakage_marker.rs` は AI モデルの内部 trace (chain-of-thought / function call signature / channel marker) がソースコードに漏出するのを検出する rule。`RE_ALL_FILES` で全拡張子を対象とし、`MARKERS` の 4 リテラルを substring match する。

| Marker                          | 由来                                                        |
| ------------------------------- | ----------------------------------------------------------- |
| `to=functions.`                 | GPT harmony format の function call signature               |
| `<\|channel\|>`                 | OpenAI harmony format の channel marker (`analysis` / `final` 等) |
| `<\|start\|>assistant`          | OpenAI harmony format の role token                         |
| `<thinking>`                    | Anthropic Claude の extended thinking tag                   |

3 つの load-bearing decision が code に潜在する。

1. **Marker 選定基準**: GPT harmony + Claude のみ。Gemini / Mistral / Llama 等の trace token は未追加。「将来 marker を追加する基準」が ADR 化されていないと、新規 AI provider 対応で marker 追加 PR ごとに review が周回する。

2. **Self-exclusion 機構**: rule 実装ファイル自体 (`src/rules/cot_leakage_marker.rs`) が全 marker をリテラルで含むため、self-edit のたびに自分自身が blocking signal を発火する。`file_path.ends_with("src/rules/cot_leakage_marker.rs")` で self-exclude する。これは「rule が自身を blocking しない」ための generic pattern で、将来 SQL injection rule (literal `' OR 1=1` を test に含む) 等で同じ問題が再発する可能性がある。

3. **Windows path separator normalize**: `file_path.replace('\\', "/")` を ends_with の前に挟む。Issue #135 で Windows 環境で self-exclude が機能せず blocking 発火する recurrence を fix (PR #136, commit 756eb66)。OUTCOME の「フロントエンドプロジェクト」想定環境は Windows (WSL ではないネイティブ) を含む。同種の path-based self-reference に対して同じ normalize が必要になる。

これらが ADR 化されていないと、(a) 新規 AI provider 対応で marker 選定基準が議論ごとにブレる、(b) 別 rule が self-reference 問題を独自実装で解決して divergence が生まれる、(c) Windows path 問題が他 path-based 判定で再発する、というリスクがある。

## Decision Drivers

- AI marker 検出の coverage は ecosystem の AI provider 主流に追随する必要がある (Claude / OpenAI が主、Gemini / Mistral / Llama 等が次点)
- rule 実装ファイルが自身を blocking する「自己干渉」問題は generic pattern として記録する価値がある
- cross-platform 動作 (Windows native 含む) の path normalize は OUTCOME の動作環境保証
- false positive (誤検出) を最小化する: marker は AI provider 固有の format で、通常ソースコードに出現する可能性が極めて低い

## Considered Options

### Marker 選定

- **A. Provider 別 marker をリテラル列挙 (採用)**: 主要 AI provider の harmony / thinking format token をリテラルで列挙
- B. Regex pattern: provider 別の正規表現で format を抽象化
- C. JSON config 外部化: user 側で marker 追加可能

### Self-exclusion

- **D. File path suffix match (採用)**: 実装ファイル path の suffix で self-exclude
- E. AST-based marker context detection: marker が test / const literal 内にあるかを AST で判定
- F. Comment marker (`// guardrails:ignore-file`) 方式: ファイル冒頭の magic comment で skip

### Path normalize

- **G. `replace('\\', "/")` で suffix match 前に正規化 (採用)**
- H. `std::path::Path::ends_with()` を使う
- I. cross-platform path crate (`camino`) を依存追加

## Decision Outcome

採用: **Option A + D + G**。Provider 別リテラル列挙 + suffix match + slash normalize。

### Scope

本 ADR は次の境界を固定する。

- `MARKERS` const は AI provider の公式 trace token のみ列挙 (regex / external config 不採用)
- 新規 provider (Gemini / Mistral 等) の marker 追加は本 ADR 改訂と PR 同時実施
- self-exclusion は file path suffix match で実装。AST context check や magic comment 方式は不採用
- self-exclusion が必要な future rule (literal bad pattern を含む rule) は本パターンを参照して同じ機構を実装する
- Windows path normalize は `replace('\\', "/")` を `ends_with` 前に挟む。`std::path::Path::ends_with()` (component-wise match) は path string 全体の literal 形と一致しないため不採用
- 全拡張子対象 (`RE_ALL_FILES`) と Severity `High` 固定は変更しない (本 rule は markdown / config / test fixture も含めて全ファイル監査する性質)

### Consequences

- Good: marker 選定基準が ADR で固定され、新規 provider 対応で review が周回しない
- Good: self-exclusion パターンが ADR で公知化、他 rule が独自実装で divergence しない
- Good: Windows path normalize の理由 (Issue #135 recurrence) が ADR で track 可能、他 path-based 判定の implement 時に同じ normalize を適用する判断材料になる
- Bad: 新規 AI provider の marker 追加が本 ADR の改訂を伴うため軽量 PR にならない
- Bad: self-exclusion が path suffix なので、`src/rules/cot_leakage_marker.rs` を rename / move すると silent に self-blocking 復活する (rename 時の checklist 追加が必要)
- Bad: regex / config 化でなくリテラル列挙のため、provider が format 変更 (例: `<|start|>assistant` → `<|start|assistant|>`) すると false negative 化

### Confirmation

`src/rules/cot_leakage_marker.rs` の test module で次を assert:
- 各 marker (`to=functions.` / `<|channel|>` / `<|start|>assistant` / `<thinking>`) の検出
- self-exclusion: `cot_leakage_marker.rs` を含む path では marker 検出されない
- Windows path normalize: `src\\rules\\cot_leakage_marker.rs` 形式の backslash path でも self-exclude

```bash
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/src/foo.ts","content":"const x = \"<thinking>internal trace</thinking>\";"}}' \
  | ./target/debug/guardrails 2>&1 | cat
```

期待: `cot-leakage-marker` で flag、severity High。

## Pros and Cons of the Options

### A. Provider 別 marker をリテラル列挙 (採用)

- Good: false positive 極小 (provider 固有 format に literal match)
- Good: 追加 / 削除のコストが低い
- Bad: format 変更追従が手動

### B. Regex pattern

- Good: format ばらつきを吸収
- Bad: 正規表現の false positive surface 拡大 (一般ソースが偶発的に match するリスク)
- Bad: regex engine の cost が逐行 scan で蓄積

### C. JSON config 外部化

- Good: user 側で provider 追加可能
- Bad: 本 audit 時点で caller 実需が観測されていない (YAGNI)、default が偏ると意味喪失

### D. File path suffix match (採用)

- Good: シンプル、AST 解析不要
- Good: rule 実装ファイル 1 つに限定された機構で十分

### E. AST-based marker context detection

- Good: rename / move 耐性
- Bad: AST 解析が逐行 substring scan より大幅にコスト増

### F. Comment marker 方式

- Good: 汎用、他 rule にも転用可能
- Bad: rule 実装ファイル冒頭に magic comment が必要、自身を ignore する宣言が rule 言明と矛盾を生む

### G. `replace('\\', "/")` で normalize (採用)

- Good: 1 行で cross-platform
- Good: 既存 `ends_with` API と組み合わせ可能

### H. `std::path::Path::ends_with()`

- Bad: component-wise match で string suffix match と semantics 違う (`src/rules/cot_leakage_marker.rs` を `["src", "rules", "cot_leakage_marker.rs"]` として比較)、Windows / Unix 切り替えで挙動差

### I. `camino` crate 追加

- Good: typed path
- Bad: dependency 追加、OUTCOME `Constraints` の起動コスト増加リスク

## More Information

### References

- `src/rules/cot_leakage_marker.rs` (実装)
- Issue #135 / PR #136 commit `756eb66` (Windows backslash normalize fix)

### Reassessment Triggers

- Gemini / Mistral / Llama / Grok 等の新 AI provider の trace token format 公式化
- 既存 marker の false positive 報告 (provider の format 変更 / 一般ソースが偶発的に match)
- rule 実装ファイル rename / 分割
- 別 rule で self-exclusion 必要性発生時、本 ADR を「self-reference pattern」の reference として参照

### Related ADRs

- なし (本 ADR が AI artifact leakage axis の最初)
