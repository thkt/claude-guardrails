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

- OUTCOME B1 と B4 の二軸 (止める / 止めない) を hook の失敗パスでも維持
- AI agent UX (誤検知で blocking が頻発すると hook が noise として無視される)
- リソース消費攻撃面 (oversized payload で bypass を試みる経路を残さない)
- 環境の fragility 現実 (network failure、oxlint update gap、AST parse 想定外)
- 新規 fail point 追加時の判定コスト (4 軸の table に当てはめるだけで決まる)

## Considered Options

- 軸ごとに固定 policy (4 軸決定表 + call site index)
- 全失敗を fail-closed (security 最大化)
- 全失敗を fail-open (UX 最大化)
- 各 call site で都度判断 (現状)

## Decision Outcome

採用: 軸ごとに固定 policy。4 つの失敗カテゴリと exit code mapping は次表の通り。

| カテゴリ                               | Policy                    | exit code                           | 理由                                                                                                                                                                         |
| -------------------------------------- | ------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 環境失敗                               | fail-open + degraded note | 0 / 1 / 2 (violation の有無で確定)  | guardrails 不可用で AI 作業を止めると UX 悪化。残存ルールでカバーし、note で degradation を AI に伝える                                                                      |
| リソース境界 / DoS 防御 (敵対入力含む) | fail-closed               | 2 (block)                           | 上限超は legitimate でも処理しない。silent truncate は false negative を生む。stdin oversized は exit 2 で block (PreToolUse で止まるのは 2 のみ。Amendment 2026-06-30 #375) |
| invariant 違反                         | fail-closed (意図)        | 70 (internal error)                 | コードの bug は速やかに通知。ただし exit 70 は block しないため現状 fail-open。exit 2 への是正は別 issue #379 で追跡 (Amendment 2026-06-30 #375)                             |
| config エラー                          | fail-open with defaults   | 0 / 1 / 2 (defaults で実行後の結果) | 壊れた config で security check を止めない。default で全 rule 有効・block_threshold=High ([ADR-0018](0018-severity-ord-and-block-threshold.md))                              |

`degraded note` は `SuccessEnvelope.notes` に文字列で積み、stderr にも eprintln する。AI agent は note を読んで「何がスキップされたか」を把握できる。

### Call Site Index

`src/hook.rs` (`lint_with_external_tools` / `lint_with_ast` / `run_hook`)、`src/io/stdin.rs` (`parse_stdin`)、`src/config.rs` (`Config::with_project_overrides` / `Config::find_git_root`)、`src/main.rs` (`install_panic_hook`) の call site (関数名で grep 可能):

| 関数                                           | 軸             | Policy 実装                                                                                  |
| ---------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------- |
| `lint_with_external_tools` (oxlint 不在)       | 環境失敗       | `"oxlint not found, JS lint skipped"` を note に積み、violations 空で返す                    |
| `lint_with_external_tools` (oxlint check 失敗) | 環境失敗       | `"oxlint check failed, JS lint skipped"` を note に積み、violations 空で返す                 |
| `lint_with_ast` (AST parse 失敗)               | 環境失敗       | `"AST parse failed, structural rules skipped"` を note に積む                                |
| `parse_stdin` (oversized)                      | リソース境界   | `MAX_INPUT_SIZE + 1` で `take`、超過時 exit 2 (block) + `DATA_ERROR` envelope                |
| `parse_stdin` (malformed JSON / stdin read)    | 環境失敗       | exit 64 + envelope。envelope は Claude Code が生成するため bug / schema drift 側 (fail-open) |
| `run_hook` (cwd canonicalize 失敗)             | 環境失敗       | warning を stderr に書き、project_root を `None` で先に進む (path-traversal boundary 無効)   |
| `Config::with_project_overrides` (parse error) | config エラー  | `eprintln!` で警告し `Config::default()` で続行                                              |
| `Config::find_git_root` (`.git` 不在)          | 環境失敗       | unchanged Config を返す (silent skip)                                                        |
| `install_panic_hook` (panic)                   | invariant 違反 | stderr に書き、`process::exit(70)`                                                           |

### Consequences

- Good, 新規 fail point 追加時に 4 軸 table に当てはめるだけで policy が決まる
- Good, AI agent への signal (exit code + envelope notes) が「何が失敗したか」「次に何をすべきか」を一貫して表現できる
- Good, 環境失敗時に security check を完全停止せず、残存 rule で部分カバー
- Bad, cwd canonicalize 失敗時の path-traversal boundary 無効化は fail-open の中でも特に外延が広い (symlink 攻撃の理論的経路)。現状は warning を stderr に書くのみで block していない
- Bad, config エラー時に user の意図 (例: 特定 rule の OFF) が defaults で上書きされる。user-visible warning は出るが、CI で気付かれない可能性

### Confirmation

各軸の policy はテストで pin されている (`cargo test` で実行)。

| 軸                       | 関連テスト                                                                                                                                           | 確認内容                               |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| 環境失敗 (oxlint 不在)   | `tests/cli/` の oxlint 不在経路                                                                                                                      | violations 空 + note 出力 + exit 0     |
| リソース境界 (oversized) | `tests/cli/dispatch.rs` の `oversized_input_blocks_with_exit_two` (`x.repeat(10_000_000)` ケース)                                                    | exit 2 (block) + `DATA_ERROR` envelope |
| invariant 違反           | `tests/cli/` の panic hook ケース                                                                                                                    | exit 70 + stderr 出力                  |
| config エラー            | `with_project_overrides_malformed_tools_json_returns_error` / `with_project_overrides_malformed_legacy_config_returns_error` (`src/config/tests.rs`) | parse error の Result<Err> 経路        |

新規 fail point を追加する PR では、軸判定 + 対応テスト追加を description に明示する。

## Pros and Cons of the Options

### 軸ごとに固定 policy (採用)

- Good, 4 軸の table が新規判定の checklist になる
- Good, OUTCOME B1/B4 と直接対応する
- Bad, 軸の境界判定 (例: 環境失敗 vs invariant 違反) で迷うケースが出る → call site index で具体化

### 全失敗 fail-closed

- Good, security 最大化、bypass 経路ゼロ
- Bad, oxlint 一時不在 (network down) で AI 作業が止まる UX
- Bad, AST parse 想定外 (oxc が edge case で panic 寸前) で全 hook が block 化

### 全失敗 fail-open

- Good, AI 作業を止めない
- Bad, 攻撃者が input を壊して security check を bypass できる
- Bad, oversized payload で OOM リスクを増やす

### 各 call site で都度判断 (現状)

- Good, 個別最適
- Bad, 横串で読むと方針不一致が出る (audit で発覚した状態)
- Bad, 新規 fail point の判定コストが毎回発生

## More Information

### Quality Attributes

| Attribute          | Priority | Approach                                                                         |
| ------------------ | -------- | -------------------------------------------------------------------------------- |
| OUTCOME B1/B4 整合 | High     | 4 軸で fail-open / fail-closed を割り振り                                        |
| AI agent UX        | High     | 環境失敗時に degraded note で signal、blocking 化はリソース境界と invariant のみ |
| 攻撃面縮減         | High     | リソース境界は fail-closed、敵対入力で bypass されない                           |
| 拡張容易性         | Medium   | 4 軸 table が新規判定の checklist になる                                         |

### Trade-offs

| 失う                                                             | 得る                                            |
| ---------------------------------------------------------------- | ----------------------------------------------- |
| cwd canonicalize 失敗時に symlink 攻撃の理論的経路が残る         | symlink を扱えない閉域環境でも hook が動く      |
| config error 時に user 意図が defaults で上書きされる            | config 壊れても security check が完全停止しない |
| 軸境界判定のオーバーヘッド (各 fail point で 4 軸のどれかを選ぶ) | 横串で読んだ時の policy 一貫性                  |

### Reassessment Triggers

- AI agent が「degraded note を読んでも何をすればよいか分からない」と報告する事象が出た場合、note 文言の見直し
- cwd canonicalize 失敗時の fail-open が実際の symlink 攻撃で悪用された場合、fail-closed への切替を検討
- 4 軸では割り振れない新カテゴリの fail point が出現した場合 (例: 非同期 timeout, IPC failure)、本 ADR を改訂
- config エラー時の defaults fallback が user の rule OFF 意図を妨げた苦情が出た場合、explicit error への切替を検討

### References

- OUTCOME.md Behavior B1 (禁止パターン → blocking) / B4 (advisory は止めない)
- `src/hook.rs` (`run_hook`, `lint_with_external_tools`, `lint_with_ast`)
- `src/io/stdin.rs` (`parse_stdin`)
- `src/main.rs` (`install_panic_hook`)
- `src/config.rs` (`with_project_overrides`, `find_git_root`)
- ADR-0005 (JSON envelope と exit code 体系)

## Amendment 2026-06-24: `.invariants.json` の読み込みは split fail-mode (Skip fail-open / Corrupt fail-closed)

2026-06-24 census で新規 ADR 昇格を見送った判断 (I3) を記録する。#359 の invariant gate が pin 宣言 file `.invariants.json` を読む際の fail-mode を、本 ADR の 4 軸の上に位置づける。

`.invariants.json` は rule の挙動を決める config ではなく、何を pin するかの data である。よって本 ADR の config error 軸 (壊れた config は defaults で fail-open) には乗らない、新しい fail point として記録する。要点は、1 つの読み込み地点 (`load_invariant_table`) が tamper signal をキーに 2 つの policy を分岐させること。

| 読み込み結果 | 条件                                                               | fail-mode                | 理由                                                                  |
| ------------ | ------------------------------------------------------------------ | ------------------------ | --------------------------------------------------------------------- |
| Skip         | file 不在、または read 失敗 (権限 / IO error)、または空 / 空白のみ | fail-open (検査せず通す) | 何も pin されていない状態。空 file で repo 全 `.json` edit を止めない |
| Corrupt      | 非空だが JSON object として parse できない                         | fail-closed (1 件 block) | tamper signal。pin file を壊して gate を黙って無効化させない          |
| Table        | 非空かつ JSON object                                               | 宣言に従い検査           | 正常系                                                                |

非対称の核心は、read 失敗 (権限 / IO error) すら Skip に倒して fail-open にすること。これは「pin file が読めない = 何も pin されていない」と扱い、repo 全体の `.json` edit を巻き込む false-block を避けるため。一方 Corrupt だけ fail-closed にするのは、攻撃者が pin file を非空のゴミで上書きして gate を無効化する経路を塞ぐため。Skip と Corrupt の境界は「空かどうか」ではなく「非空で object でないか」に置く。

### Related (I3)

- `src/invariant.rs` (`load_invariant_table`, `InvariantLoad`, `run_invariant_pass`)
- ADR-0004 本文 4 軸 (環境失敗 fail-open / config error fail-open-with-defaults との対比)
- ADR-0023 (stateless path-consistent invariant gate)

## Amendment 2026-06-30: fail-closed は exit 2 で実現する、exit 64 は block しない (#375)

本 ADR 初版はリソース境界軸を「fail-closed → exit 64 (input error)」と記録し、oversized payload を exit 64 で止める想定だった。これは PreToolUse 契約の誤読である。公式 hooks ドキュメント (https://code.claude.com/docs/en/hooks.md) では tool 呼び出しを止めるのは exit 2 のみ。0 は allow、それ以外の非ゼロ (1 / 64 / 70) は non-blocking で tool を続行させる。よって exit 64 を返す `parse_stdin` (oversized) は実際には fail-open であり、10 MB 超の payload が検査を素通りしていた (OUTCOME.md の「oversized payload で bypass を試みる経路を残さない」driver に反する)。

是正は `ParseStdinError` の variant 単位で行う。判定軸は「その失敗を agent が bypass の梃子として制御できるか」。

| variant       | 制御可能性                                       | exit code         | fail-mode   |
| ------------- | ------------------------------------------------ | ----------------- | ----------- |
| `Oversized`   | agent が content size を決められる (bypass 経路) | 2 (block)         | fail-closed |
| `InvalidJson` | envelope は Claude Code が生成 (agent 梃子なし)  | 64 (`InputError`) | fail-open   |
| `Io`          | stdin read failure は環境側 (agent 梃子なし)     | 64 (`InputError`) | fail-open   |

`InvalidJson` / `Io` を fail-open に残すのは、これらを block すると Claude Code 側の envelope schema drift で全編集が止まる自滅 DoS を招くため。リソース境界軸の中でも「agent が制御可能か」で fail-closed / fail-open を分ける。

invariant 違反軸 (`install_panic_hook`, exit 70) も同じ契約で block しない。本文表で「fail-closed (意図)」と注記した通り現状は fail-open である。exit 2 への是正は stdin parse 軸とは別の失敗軸であり、本 #375 の scope 外として別 issue #379 で追跡する。

### Related (Amendment 2026-06-30)

- `src/io/stdin.rs` (`ParseStdinError::hook_exit_code`, `parse_stdin`)
- `src/hook.rs` (`run_hook` の exit code 振り分け)
- ADR-0005 Amendment 2026-06-30 (exit code table の block 列訂正と envelope 対応)
- 公式 PreToolUse hooks 契約 (https://code.claude.com/docs/en/hooks.md): 「only exit code 2 blocks the action」
