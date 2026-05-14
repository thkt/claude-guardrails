---
status: "accepted"
date: 2026-05-14
decision-makers: thkt
---

# Fail-mode policy

## Context and Problem Statement

guardrails は AI エージェントの PreToolUse hook として、外部リンタ呼び出し / AST parse / file I/O / config 読み込み / stdin 解析 / cwd 解決 / panic 等、複数の失敗ポイントを抱えている。これらに対する fail-open (pass + note) と fail-closed (block + error) の方針が `src/main.rs` と `src/config.rs` に散在しており、新しい失敗パスを追加する時に「どちらが正しいか」を判断する基準が不在だった。

OUTCOME.md Behavior B1 (禁止パターンは blocking signal で止める) と B4 (advisory は止めずに通す) を踏まえると、失敗パスの分類軸を「環境失敗 / リソース境界 / invariant 違反 / config エラー」の 4 つに固定し、各軸ごとに policy を 1 つに決めるべきと判断した。

## Decision Drivers

* OUTCOME B1 と B4 の二軸 (止める / 止めない) を hook の失敗パスでも維持
* AI agent UX (誤検知で blocking が頻発すると hook が noise として無視される)
* リソース消費攻撃面 (oversized payload で bypass を試みる経路を残さない)
* 環境の fragility 現実 (network failure、oxlint update gap、AST parse 想定外)
* 新規 fail point 追加時の判定コスト (4 軸の table に当てはめるだけで決まる)

## Considered Options

* 軸ごとに固定 policy (4 軸決定表 + call site index)
* 全失敗を fail-closed (security 最大化)
* 全失敗を fail-open (UX 最大化)
* 各 call site で都度判断 (現状)

## Decision Outcome

採用: 軸ごとに固定 policy。4 つの失敗カテゴリと exit code mapping は次表の通り。

| カテゴリ | Policy | exit code | 理由 |
| --- | --- | --- | --- |
| 環境失敗 | fail-open + degraded note | 0 / 1 / 2 (violation の有無で確定) | guardrails 不可用で AI 作業を止めると UX 悪化。残存ルールでカバーし、note で degradation を AI に伝える |
| リソース境界 / DoS 防御 (敵対入力含む) | fail-closed | 64 (input error) | 上限超は legitimate でも処理しない。silent truncate は false negative を生む |
| invariant 違反 | fail-closed | 70 (internal error) | コードの bug は速やかに通知。次の hook 起動でも同じ panic が出れば修正が必要 |
| config エラー | fail-open with defaults | 0 / 1 / 2 (defaults で実行後の結果) | 壊れた config で security check を止めない。default で全 rule 有効・block_on=[Critical, High] |

`degraded note` は `SuccessEnvelope.notes` に文字列で積み、stderr にも eprintln する。AI agent は note を読んで「何がスキップされたか」を把握できる。

### Call Site Index

`src/main.rs` と `src/config.rs` の call site (lines accurate at 2026-05-14; 関数名で grep 可能):

| 関数 | 軸 | Policy 実装 |
| --- | --- | --- |
| `lint_with_external_tools` (oxlint 不在) | 環境失敗 | `"oxlint not found, JS lint skipped"` を note に積み、violations 空で返す |
| `lint_with_external_tools` (oxlint check 失敗) | 環境失敗 | `"oxlint check failed, JS lint skipped"` を note に積み、violations 空で返す |
| `lint_with_ast` (AST parse 失敗) | 環境失敗 | `"AST parse failed, structural rules skipped"` を note に積む |
| `parse_stdin` (oversized) | リソース境界 | `MAX_INPUT_SIZE + 1` で `take`、超過時 exit 64 + `DATA_ERROR` envelope |
| `run_hook` (cwd canonicalize 失敗) | 環境失敗 | warning を stderr に書き、project_root を `None` で先に進む (path-traversal boundary 無効) |
| `Config::with_project_overrides` (parse error) | config エラー | `eprintln!` で警告し `Config::default()` で続行 |
| `Config::find_git_root` (`.git` 不在) | 環境失敗 | unchanged Config を返す (silent skip) |
| `install_panic_hook` (panic) | invariant 違反 | stderr に書き、`process::exit(70)` |

### Consequences

* Good, 新規 fail point 追加時に 4 軸 table に当てはめるだけで policy が決まる
* Good, AI agent への signal (exit code + envelope notes) が「何が失敗したか」「次に何をすべきか」を一貫して表現できる
* Good, 環境失敗時に security check を完全停止せず、残存 rule で部分カバー
* Bad, cwd canonicalize 失敗時の path-traversal boundary 無効化は fail-open の中でも特に外延が広い (symlink 攻撃の理論的経路)。現状は warning を stderr に書くのみで block していない
* Bad, config エラー時に user の意図 (例: 特定 rule の OFF) が defaults で上書きされる。user-visible warning は出るが、CI で気付かれない可能性

### Confirmation

各軸の policy はテストで pin されている (`cargo test` で実行)。

| 軸 | 関連テスト | 確認内容 |
| --- | --- | --- |
| 環境失敗 (oxlint 不在) | `tests/integration.rs` の oxlint 不在経路 | violations 空 + note 出力 + exit 0 |
| リソース境界 (oversized) | `tests/integration.rs` の `x.repeat(10_000_000)` ケース | exit 64 + `DATA_ERROR` envelope |
| invariant 違反 | `tests/integration.rs` の panic hook ケース | exit 70 + stderr 出力 |
| config エラー | `with_project_overrides_malformed_tools_json_returns_error` / `with_project_overrides_malformed_legacy_config_returns_error` (`src/config.rs`) | parse error の Result<Err> 経路 |

新規 fail point を追加する PR では、軸判定 + 対応テスト追加を description に明示する。

## Pros and Cons of the Options

### 軸ごとに固定 policy (採用)

* Good, 4 軸の table が新規判定の checklist になる
* Good, OUTCOME B1/B4 と直接対応する
* Bad, 軸の境界判定 (例: 環境失敗 vs invariant 違反) で迷うケースが出る → call site index で具体化

### 全失敗 fail-closed

* Good, security 最大化、bypass 経路ゼロ
* Bad, oxlint 一時不在 (network down) で AI 作業が止まる UX
* Bad, AST parse 想定外 (oxc が edge case で panic 寸前) で全 hook が block 化

### 全失敗 fail-open

* Good, AI 作業を止めない
* Bad, 攻撃者が input を壊して security check を bypass できる
* Bad, oversized payload で OOM リスクを増やす

### 各 call site で都度判断 (現状)

* Good, 個別最適
* Bad, 横串で読むと方針不一致が出る (audit で発覚した状態)
* Bad, 新規 fail point の判定コストが毎回発生

## More Information

### Quality Attributes

| Attribute | Priority | Approach |
| --- | --- | --- |
| OUTCOME B1/B4 整合 | High | 4 軸で fail-open / fail-closed を割り振り |
| AI agent UX | High | 環境失敗時に degraded note で signal、blocking 化はリソース境界と invariant のみ |
| 攻撃面縮減 | High | リソース境界は fail-closed、敵対入力で bypass されない |
| 拡張容易性 | Medium | 4 軸 table が新規判定の checklist になる |

### Trade-offs

| 失う | 得る |
| --- | --- |
| cwd canonicalize 失敗時に symlink 攻撃の理論的経路が残る | symlink を扱えない閉域環境でも hook が動く |
| config error 時に user 意図が defaults で上書きされる | config 壊れても security check が完全停止しない |
| 軸境界判定のオーバーヘッド (各 fail point で 4 軸のどれかを選ぶ) | 横串で読んだ時の policy 一貫性 |

### Reassessment Triggers

* AI agent が「degraded note を読んでも何をすればよいか分からない」と報告する事象が出た場合、note 文言の見直し
* cwd canonicalize 失敗時の fail-open が実際の symlink 攻撃で悪用された場合、fail-closed への切替を検討
* 4 軸では割り振れない新カテゴリの fail point が出現した場合 (例: 非同期 timeout, IPC failure)、本 ADR を改訂
* config エラー時の defaults fallback が user の rule OFF 意図を妨げた苦情が出た場合、explicit error への切替を検討

### References

* OUTCOME.md Behavior B1 (禁止パターン → blocking) / B4 (advisory は止めない)
* `src/main.rs` (`parse_stdin`, `run_hook`, `install_panic_hook`, `lint_with_external_tools`, `lint_with_ast`)
* `src/config.rs` (`with_project_overrides`, `find_git_root`)
* ADR-0005 (JSON envelope と exit code 体系)
* Audit: `docs/audit/2026-05-14-undocumented-decisions.md` Cluster A
