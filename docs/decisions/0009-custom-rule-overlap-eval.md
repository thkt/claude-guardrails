---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# eval 検出を custom AST rule に集約し oxlint の同等 rule を抑止する

## Context and Problem Statement

`.ts` ファイルに `eval(userInput);` を書いた際、同一 file:line に対して 2 件の違反が出力される。

| 発火元              | rule_id                          | severity | 検出範囲                                                                                          |
| ------------------- | -------------------------------- | -------- | ------------------------------------------------------------------------------------------------- |
| oxlint 既定         | `eslint(no-eval)`                | MEDIUM   | direct call (`eval(...)`)                                                                         |
| `src/rules/eval.rs` | `eval`                           | HIGH     | direct call, `new Function(...)`, `window.eval`, `globalThis.eval`, import alias, namespace member (`ns.eval`), CJS destructuring, bracket notation (`window["eval"]`) |

AI agent から見ると同じ修正対象が 2 回 listing され、`BLOCKED: Fix 1 issue` の footer 件数とも食い違うため、修正対象数を誤認するリスクがある。これは OUTCOME の「フィードバックの精度と AI エージェントの体験を継続的に高める」に反する。

## Decision Drivers

- 同一 file:line の重複表示を排除し、修正対象数表示と footer 件数を一致させる
- custom AST 側のリッチな検出 (alias / namespace / CJS / bracket) を温存する
- HIGH severity を維持し、blocking を確実に発火させる
- 起動コストを増やさない (hook は AI の編集毎に呼ばれる)
- 横展開時の追加コストを最小化する

## Considered Options

- A. oxlint が検出した rule_id は custom rule 側で skip (oxlint 優先)
- B. custom rule が責務を持つ oxlint rule を subprocess の `--allow` で抑止し、custom rule に集約 (採用)
- C. reporter 層で rule 名マッピング表による dedup

## Decision Outcome

採用: **Option B**。`src/oxlint.rs` の `build_args` で oxlint subprocess に `--allow eslint/no-eval` を常時渡し、eval の検出責務を `src/rules/eval.rs` の AST 検出 (`rule_id::EVAL`, HIGH) に集約する。custom 側は変更しない。

選定対象を表に集約する定数を導入:

```rust
const OXLINT_OVERLAP_ALLOW: &[&str] = &["eslint/no-eval"];
```

`build_args` で `OXLINT_OVERLAP_ALLOW` を `--allow <rule>` として subprocess 引数に展開する。ユーザー `config.deny` に同じ rule_id が含まれても上書きはせず、`--deny` と `--allow` の双方が引数列に出るが、oxlint CLI は左から右に処理し最後の指定 (= `--allow`) が勝つため、custom rule に責務が残る。

### Scope

本 ADR は `eslint/no-eval` 1 件のみを対象とする。`eslint/no-console`, `typescript/no-non-null-assertion` など他の overlap については本 issue (#124) では扱わない。横展開判断は別 issue で行う。

### Consequences

- Good: AI agent が読む違反 listing から重複行が消え、修正対象数の誤認を防ぐ
- Good: custom AST 検出 (alias / namespace / CJS / bracket) を失わない
- Good: HIGH severity を維持し、blocking が確実に発火する
- Good: subprocess 引数を 2 個 (`--allow`, `<rule>`) 増やすだけで起動コスト変化は無視できる
- Good: 将来 oxlint 側が同等以上の AST 検出をリリースしたとき、`OXLINT_OVERLAP_ALLOW` から該当 entry を外し custom rule を retire するルートが残る
- Bad: oxlint config (`config.allow` / `config.deny`) を通じてユーザーが `eslint/no-eval` を有効化することは出来なくなる。ユーザー観点では「custom `eval` rule で同等以上の検出をしている」ため実害は無いが、契約として README に明記する必要がある
- Bad: 将来 overlap が増えたとき、新 rule_id を `OXLINT_OVERLAP_ALLOW` に追加し ADR を作成する手間が rule ごとに発生する

### Verification

- `src/oxlint.rs` の unit test `build_args_allows_eval_to_defer_to_custom_rule` で `--allow eslint/no-eval` 引数の出力を assert
- `src/oxlint.rs` の unit test `build_args_overlap_allow_holds_even_with_user_deny` でユーザー `config.deny` 同 rule 指定下でも `--allow` が残ることを assert
- `tests/integration.rs` の `json_mode_violation_emits_block_decision` で eval を含む `.ts` に対し JSON envelope の `violations` に `rule == "eval"` が含まれ、`rule == "oxlint/eslint(no-eval)"` が含まれないことを negative assertion で固定
