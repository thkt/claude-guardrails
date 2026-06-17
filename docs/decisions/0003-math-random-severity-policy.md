---
status: "accepted"
date: 2026-05-14
decision-makers: thkt
---

# Math.random ルールの severity policy

## Context and Problem Statement

guardrails は AI エージェント向け hook として、AST 解析で検出した violation を `Severity` で分類し、`config.severity.block_threshold` 以上かで exit code (blocking=2 / advisory=1) を決定する (`src/hook_exit.rs`, `src/hook.rs` の `partition_violations`)。default `block_threshold = High` (`src/config.rs` の `SeverityConfig::default()`、[ADR-0018](0018-severity-ord-and-block-threshold.md) で `block_on` 集合から置換)。

既存 `Math.random().toString(36)` (`src/analysis/ast_security/math_random.rs` の `check_math_random_insecure` / `check_math_random_crypto_sink`) は `Severity::Medium` で実装されており、default block_threshold (High) 未満、つまり default では Advisory (exit 1) しか出さない。これは OUTCOME.md Behavior B1「禁止パターン → blocking signal → 同サイクル修正」と齟齬する。Issue #80 で検出範囲を拡張する際、各検出パターンを blocking と advisory のどちらに振るかの判断基準が必要になった。

## Decision Drivers

- OUTCOME B1 と B4 を hook 設計の二軸として保つ (blocking と advisory の使い分け)
- 既存 ast_security ルールの severity 一貫性
- AI エージェントの編集体験 (FP が blocking 化すると hook を noise として無視されるリスク)
- 設定拡張コスト (`define_rule_config!` macro は現状 `Option<bool>` のみ)

## Considered Options

- 用法確定性で blocking/advisory を分ける (採用)
- 全パターン Medium (default Advisory)
- 全パターン High (default Blocking)
- severity を project config で上書き可能化

## Decision Outcome

採用: 用法確定性 (usage-determinacy) で severity を決定。

| パターン分類                              | Severity     | Default exit      | 例                                                                                                 |
| ----------------------------------------- | ------------ | ----------------- | -------------------------------------------------------------------------------------------------- |
| 用法確定 (固定イディオム / 暗号 API 引数) | High         | Blocking (exit 2) | `Math.random().toString(36)` / `bcrypt.hash(_, Math.random())`                                     |
| 用法不確定 (heuristic)                    | Medium       | Advisory (exit 1) | `const token = Math.random()` / `function generateToken()` 内 Math.random / `.toString()` チェーン |
| 用法明白 pass                             | (検出対象外) | (exit 0)          | React JSX key / setTimeout jitter / 乗算式 / テストファイル                                        |

### Consequences

- Good, OUTCOME B1 と B4 の使い分けがコード上で明示的になる
- Good, AI エージェントが blocking と advisory の意味を信頼できる (blocking = 用法確定的に誤り)
- Good, 用法確定性の枠組みは他 ast_security ルール (innerHTML / document.write / prototype pollution 等) の severity 再評価でも参照できる
- Bad, 既存 `Math.random().toString(36)` が Medium → High に変わる BREAKING。既存 PR で通った token 生成コードは新版で blocking 化する
- Bad, 既存テスト T-011 (`math_random_insecure_to_string_36_blocked` in `src/analysis/ast_security/math_random/tests.rs`) の severity assertion を Medium → High に更新する必要

### Confirmation

新規ルール追加 PR で severity 選択が用法確定性のどの分類に該当するかを PR description に明示することを運用ルールとする。テスト T-011 が High を assert し、新規 heuristic テスト群 (T-022 以降) が Medium を assert することで、実装と policy の対応をテストで検証する。

## Pros and Cons of the Options

### 用法確定性で blocking/advisory を分ける

- Good, OUTCOME 二軸を直接マップする
- Good, 用法確定性は既存パターン (React key / 乗算式 = pass、token 生成 = blocking) と矛盾しない
- Bad, BREAKING を含む

### 全パターン Medium (default Advisory)

- Good, 下位互換性完全
- Bad, OUTCOME B1 と齟齬。unsafe token が advisory 止まりで素通り

### 全パターン High (default Blocking)

- Good, セキュリティ最大化
- Bad, heuristic FP が blocking 化 → AI エージェント UX 悪化、OUTCOME B4 と齟齬

### severity を project config で上書き可能化

- Good, project 個別調整可能
- Bad, `define_rule_config!` macro 拡張コスト発生、call site 0 で YAGNI

## More Information

### Quality Attributes

| Attribute    | Priority | Approach                     |
| ------------ | -------- | ---------------------------- |
| OUTCOME 整合 | High     | 用法確定性で severity 決定   |
| AI agent UX  | High     | heuristic は advisory 止まり |
| 互換性       | Low      | BREAKING 受容                |

### Trade-offs

下位互換性を犠牲にして OUTCOME 整合と AI agent への信頼できるシグナルを得る。

### Reassessment Triggers

- 用法確定性が判定困難な新パターン (例: 文脈依存度が極端に高い semantic 検出) が出てきた場合
- AI エージェントが blocking を頻繁に bypass する事象が観測された場合
- `define_rule_config!` macro が `Vec<String>` を受けるよう拡張された場合 (config 上書き可能化を再検討)
