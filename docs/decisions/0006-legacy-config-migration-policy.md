---
status: "accepted"
date: 2026-05-14
decision-makers: thkt
---

# Legacy config migration policy

## Context and Problem Statement

guardrails の設定ファイルは現在 `.claude/tools.json` (`guardrails` キー配下) を一次取得先とし、レガシーの `.claude-guardrails.json` を二次取得先として並走させている。`.claude/tools.json` 採用の動機は guardrails が `formatter` / `reviews` / `gates` と並ぶ 4-tool quality pipeline の一部であり、複数 hook tool の設定を `.claude/tools.json` に集約する方針 (README "Companion Tools" 参照) に揃えるためである。

並走の意味づけ (どちらが優先か、両方ある時の挙動、レガシーの廃止時期、廃止時の通知方法) が `src/config.rs` の実装と README の "Migration" 注記に断片化しており、user 質問が来た時に「いつ消えるか」「並走中の優先順序」を一貫して説明できない状態だった。

## Decision Drivers

* 既存 user の `.claude-guardrails.json` を破壊しない (backward compat)
* 4-tool quality pipeline で `.claude/tools.json` に統一する方向と整合
* config 移行を user に強制せず、user 主導の opt-in 移行を促す
* `.claude/tools.json` に他 tool の設定がある状態 (guardrails キー無し) で legacy を silent read する事故を防ぐ

## Considered Options

* `.claude/tools.json` 優先 + legacy fallback + tools.json 存在で legacy skip (採用)
* `.claude-guardrails.json` 即廃止 (BREAKING)
* 両方読んで merge (legacy 上書き tools.json)
* deprecation warning を出して移行を強制

## Decision Outcome

採用: `.claude/tools.json` (新) を一次、`.claude-guardrails.json` (レガシー) を二次とする探索順序。並走期間中の優先順序と廃止条件は次表の通り。

### 探索順序

`Config::with_overrides_from_root` (`src/config.rs`) の挙動:

| ステップ | 対象 | 挙動 |
| --- | --- | --- |
| 1 | `.git` を探索開始ディレクトリから ancestors() で探す | 不在なら unchanged Config を silent return (fail-open: 環境失敗) |
| 2 | `.claude/tools.json` を read | parse 失敗は `Err(String)` で hook fail (config エラー軸、`Config::default()` で続行) |
| 3 | `tools.json` 内 `guardrails` key の有無 | `Some` なら merge して return (legacy skip)、`None` でも tools.json 存在を理由に legacy skip |
| 4 | `.claude-guardrails.json` を read | tools.json が見つかっていない場合のみ参照。parse 失敗は同上 |

ステップ 3 が重要: `.claude/tools.json` が存在しても guardrails キーが無い (例: `formatter` / `reviews` の設定のみ) 場合、それは「user が 4-tool pipeline に乗っている」状態であり、legacy を別途読むと既存 user の意図と乖離する。tools.json 存在だけで legacy を skip する。

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

* Good, 既存 `.claude-guardrails.json` user は変更不要
* Good, 4-tool quality pipeline 採用 user は `.claude/tools.json` に集約できる
* Good, tools.json 存在 + guardrails キー不在のケースで silent legacy read を避けられる
* Bad, 両方 存在する場合 legacy が ignored される (user が気付かない可能性)。README で明示するが warning は出さない方針
* Bad, 並走期間の終了条件が「v1.0 + 6 ヶ月」と (b) のいずれか先で、(b) を観測する仕組みが現状無い

### Confirmation

探索順序と優先関係は次のテストで pin されている (`src/config.rs`)。

| 確認内容 | テスト |
| --- | --- |
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

### tools.json 優先 + legacy fallback + tools.json 存在で legacy skip (採用)

* Good, 既存 user 変更不要 (backward compat)
* Good, 4-tool pipeline 採用 user が tools.json に集約できる
* Good, tools.json 存在で legacy を silent read しないことを明示
* Bad, 両方ある時 legacy が ignored される (user 気付き難い)

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
| Backward compat | High | 並走期間中 legacy を読む |
| 4-tool pipeline 整合 | High | tools.json を一次、guardrails キー不在でも tools.json 存在で legacy skip |
| User UX (移行強制しない) | Medium | deprecation warning なし、自然な移行を待つ |
| 廃止可能性 | Medium | v1.0 + 6 ヶ月で廃止 PR を作る前提 |

### Trade-offs

| 失う | 得る |
| --- | --- |
| 両方ある時 legacy ignored で user が気付かない | 4-tool pipeline 採用時の混乱を避ける |
| 並走期間中 code path が複数 (tools.json / legacy / both) | 既存 user の migration を強制しない |
| 廃止 timing が ecosystem 観測依存で曖昧 | rigid timeline で user を急かさない |

### Reassessment Triggers

* v1.0 リリース時 (status: superseded を予告するか、廃止 PR を切る)
* `.claude-guardrails.json` の使用報告がゼロになったことを観測できた場合 (廃止 PR を加速)
* tools.json + legacy 両方ある user から「ignored で気付かない」苦情が複数出た場合、deprecation warning 導入を検討
* 別 hook tool (formatter / reviews / gates) で `.claude/tools.json` 探索順序が変わった場合、整合のため本 ADR を改訂

### References

* `src/config.rs` (`with_overrides_from_root`, `find_git_root`, `merge`, `TOOLS_CONFIG_FILE`, `LEGACY_CONFIG_FILE`)
* `README.md` の "Configuration" / "Config Resolution" / "Migration" セクション
* `README.md` の "Companion Tools" (4-tool pipeline)
