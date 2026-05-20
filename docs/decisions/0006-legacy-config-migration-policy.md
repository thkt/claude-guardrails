---
status: "accepted"
date: 2026-05-20
decision-makers: thkt
---

# Config file search policy

## Context and Problem Statement

guardrails の設定ファイルは元々 `.claude/tools.json` (`guardrails` キー配下) を一次取得先とし、レガシーの `.claude-guardrails.json` を二次取得先として並走させていた。`.claude/tools.json` 採用の動機は guardrails が `formatter` / `reviews` / `gates` と並ぶ 4-tool quality pipeline の一部であり、複数 hook tool の設定を `.claude/tools.json` に集約する方針 (README "Companion Tools" 参照) に揃えるためである。

その後、guardrails を Claude Code 以外の AI agent (codex CLI, Cursor 等) からも hook として起動するニーズが出てきた。`.claude/` 配下に config を縛ると agent-specific になり、複数 agent を同 repo で使う user は同じ設定を duplicate せざるを得ない。この摩擦を消すため agent-neutral な root path を一次として導入する。

並走の意味づけ (どちらが優先か、両方ある時の挙動、レガシーの廃止時期、廃止時の通知方法) も `src/config.rs` の実装と README の "Migration" 注記に断片化しており、user 質問が来た時に「いつ消えるか」「並走中の優先順序」を一貫して説明できない状態だった。

## Decision Drivers

* agent-neutral な path で codex / Cursor 等の他 AI agent からも同じ config を読めるようにする
* 既存 user の `.claude-guardrails.json` / `.claude/tools.json` を破壊しない (backward compat)
* 4-tool quality pipeline で `.claude/tools.json` に統一する方向 (Claude Code user 向け) と整合
* config 移行を user に強制せず、user 主導の opt-in 移行を促す
* `.claude/tools.json` に他 tool の設定がある状態 (guardrails キー無し) で legacy を silent read する事故を防ぐ

## Considered Options

* `.guardrails.json` (agent-neutral) を一次に追加 + `.claude/tools.json` を二次 + legacy を三次 (採用)
* `.codex/tools.json` / `.cursor/tools.json` 等 agent ごとに path を追加
* `GUARDRAILS_CONFIG_PATH` env で path 上書きのみ提供
* `.claude-guardrails.json` 即廃止 (BREAKING)
* 両方読んで merge (legacy 上書き tools.json)
* deprecation warning を出して移行を強制

## Decision Outcome

採用: `.guardrails.json` (agent-neutral, 新) を一次、`.claude/tools.json` (4-tool pipeline 集約用) を二次、`.claude-guardrails.json` (legacy) を三次とする探索順序。

### 探索順序

`Config::with_overrides_from_root` (`src/config.rs`) の挙動:

| ステップ | 対象 | 挙動 |
| --- | --- | --- |
| 1 | `.git` を探索開始ディレクトリから ancestors() で探す | 不在なら unchanged Config を silent return (fail-open: 環境失敗) |
| 2 | `.guardrails.json` を read (flat `ProjectConfig`) | parse 失敗は `Err(String)` で hook fail。read 成功なら merge して return (他 path は skip) |
| 3 | `.claude/tools.json` を read | parse 失敗は `Err(String)` で hook fail (config エラー軸、`Config::default()` で続行) |
| 4 | `tools.json` 内 `guardrails` key の有無 | `Some` なら merge して return (legacy skip)、`None` でも tools.json 存在を理由に legacy skip |
| 5 | `.claude-guardrails.json` を read | tools.json も `.guardrails.json` も見つかっていない場合のみ参照。parse 失敗は同上 |

ステップ 2 が新規追加: `.guardrails.json` は agent から独立した root path で、format は flat `ProjectConfig` (legacy と同じ、`guardrails` key で wrap しない)。存在すれば他 path を skip して終了する。これは user が agent-neutral path を意図的に置いた状態を尊重するため。

ステップ 4 が重要: `.claude/tools.json` が存在しても guardrails キーが無い (例: `formatter` / `reviews` の設定のみ) 場合、それは「user が 4-tool pipeline に乗っている」状態であり、legacy を別途読むと既存 user の意図と乖離する。tools.json 存在だけで legacy を skip する。

### 並走期間と廃止条件

| 項目 | 内容 |
| --- | --- |
| 並走開始 | v0.x (現状) |
| 廃止予告 | v1.0 リリース notes に明記、README "Migration" セクションを update |
| 廃止実施 | v1.0 以降の任意の minor で `.claude-guardrails.json` 読み込みパスを削除 (BREAKING) |
| 廃止条件 | (a) v1.0 release から 6 ヶ月経過、または (b) ecosystem (homebrew / sentinels plugin / 主要 user repo) の `.claude-guardrails.json` 利用が観測されなくなった、のいずれか先 |

silent deprecation warning は出さない: 並走中は migration を強制しない方針。user が `.claude/tools.json` に乗り換えるトリガは 4-tool pipeline 採用などの自然な動機に任せる。

### git worktree のサポート

`Config::find_git_root` は `Path::join(".git").exists()` で判定している。`Path::exists()` はファイル / ディレクトリの両方を true で返すため、`.git` が file (worktree の case) でも root として検出される。`.git` directory が無い state でも worktree なら gitdir reference file が `.git` 名で配置されているため、現状の実装で worktree を別 fix なしでサポートしている。

### Consequences

* Good, agent-neutral `.guardrails.json` で codex / Cursor 等の他 AI agent からも同じ設定を共有できる
* Good, 既存 `.claude/tools.json` / `.claude-guardrails.json` user は変更不要
* Good, 4-tool quality pipeline 採用 user は `.claude/tools.json` に引き続き集約できる
* Good, tools.json 存在 + guardrails キー不在のケースで silent legacy read を避けられる
* Bad, 複数 path が並走する状態が長期化すると user が「どこに書けばいいか」を判断しづらい (README で `.guardrails.json` 推奨を明示)
* Bad, 並走期間の終了条件が「v1.0 + 6 ヶ月」と (b) のいずれか先で、(b) を観測する仕組みが現状無い

### Confirmation

探索順序と優先関係は次のテストで pin されている (`src/config.rs`)。

| 確認内容 | テスト |
| --- | --- |
| `.guardrails.json` から override 取得 | `with_project_overrides_from_guardrails_json` |
| `.guardrails.json` 優先 (vs tools.json) | `with_project_overrides_guardrails_json_takes_priority_over_tools_json` |
| `.guardrails.json` 優先 (vs legacy) | `with_project_overrides_guardrails_json_takes_priority_over_legacy` |
| `.guardrails.json` parse 失敗で error | `with_project_overrides_malformed_guardrails_json_returns_error` |
| tools.json から override 取得 | `with_project_overrides_from_tools_json` |
| legacy から override 取得 | `with_project_overrides_from_legacy_config` |
| 両方ある時 tools.json 優先 | `with_project_overrides_tools_json_takes_priority` |
| tools.json 存在 + guardrails キー無し → legacy skip | `with_project_overrides_tools_json_without_guardrails_ignores_legacy` |
| tools.json parse 失敗で error | `with_project_overrides_malformed_tools_json_returns_error` |
| legacy parse 失敗で error | `with_project_overrides_malformed_legacy_config_returns_error` |
| `.git` 不在で silent unchanged | `find_git_root_none_without_git` |
| 深いサブディレクトリから git root 検出 | `find_git_root_from_deep_subdir` |

legacy 廃止 PR では本 ADR の status を `superseded by ADR-NNNN` に書き換える。

## Pros and Cons of the Options

### `.guardrails.json` を一次に追加 + tools.json 二次 + legacy 三次 (採用)

* Good, agent-neutral root path で複数 AI agent から同じ設定を読める
* Good, 既存 user 変更不要 (backward compat)
* Good, 4-tool pipeline 採用 user は `.claude/tools.json` を引き続き使える
* Good, tools.json 存在で legacy を silent read しないことを明示
* Bad, 並走 path が 3 つに増え、user が「どこに書けばいいか」迷う (README で一次推奨を明示)

### agent ごとに path を追加 (`.codex/tools.json` 等)

* Good, 各 agent の 4-tool pipeline 思想を尊重できる
* Bad, agent が増えるごとに path が増える (Cursor, Aider, Continue, …)
* Bad, 同 repo で複数 agent を使う user は同じ設定を duplicate する

### `GUARDRAILS_CONFIG_PATH` env のみ

* Good, 最小変更
* Bad, discoverability が低い (env を知らない user は config できない)
* Bad, hook 起動側で env を毎回 inject する運用が必要

### 即廃止 (BREAKING)

* Good, code path 単純化
* Bad, 既存 user の migration 強制、苦情リスク
* Bad, v1.0 前の BREAKING は semver 規約と整合しない

### 両方読んで merge (legacy 上書き tools.json)

* Good, 二段階移行 (新 config を tools.json に書きながら legacy で fallback)
* Bad, merge 順序の意味づけが exotic で、user が「どちらが効くか」を予想できない
* Bad, 両方の同 key が異なる値だった時の挙動が surprising

### deprecation warning で移行強制

* Good, user が移行に気付く
* Bad, hook output に warning が混入し、AI agent が note として誤解釈する可能性
* Bad, 移行コスト (config 書き換え) を user に強制する

## More Information

### Quality Attributes

| Attribute | Priority | Approach |
| --- | --- | --- |
| Agent-neutral 性 | High | `.guardrails.json` を一次として agent dir に縛られない path を提供 |
| Backward compat | High | 並走期間中 legacy を読む、tools.json も二次として継続 |
| 4-tool pipeline 整合 | High | `.claude/tools.json` を二次、guardrails キー不在でも tools.json 存在で legacy skip |
| User UX (移行強制しない) | Medium | deprecation warning なし、自然な移行を待つ |
| 廃止可能性 | Medium | v1.0 + 6 ヶ月で legacy 廃止 PR を作る前提 (tools.json は当面維持) |

### Trade-offs

| 失う | 得る |
| --- | --- |
| 並走 path が 3 つに増え user が迷う | agent-neutral root path で複数 agent 対応 |
| 並走期間中 code path が複数 | 既存 user の migration を強制しない |
| 廃止 timing が ecosystem 観測依存で曖昧 | rigid timeline で user を急かさない |

### Reassessment Triggers

* `.guardrails.json` 採用率が高まり `.claude/tools.json` 利用が観測されなくなった場合、tools.json を deprecated 扱いに移行する PR を検討
* v1.0 リリース時 (status: superseded を予告するか、legacy 廃止 PR を切る)
* `.claude-guardrails.json` の使用報告がゼロになったことを観測できた場合 (廃止 PR を加速)
* 複数 path 並走で user から「どこに書けばいいか」苦情が複数出た場合、README で一次推奨をより強く明示
* 別 hook tool (formatter / reviews / gates) で `.claude/tools.json` 探索順序が変わった場合、整合のため本 ADR を改訂

### References

* `src/config.rs` (`with_overrides_from_root`, `find_git_root`, `merge`, `GUARDRAILS_CONFIG_FILE`, `TOOLS_CONFIG_FILE`, `LEGACY_CONFIG_FILE`)
* `README.md` の "Configuration" / "Config Resolution" / "Migration" セクション
* `README.md` の "Companion Tools" (4-tool pipeline)
