---
status: "accepted"
date: 2026-08-14
decision-makers: thkt
---

# `.guardrails.json` の `overrides` でルール適用をパス glob 単位に絞る

## Context and Problem Statement

`.guardrails.json` の `rules` は project 全体に一括で効く。1 project の中でも directory ごとに許容度は違う。例えば `testAssertion` は fixture directory の中身まで検査するが、fixture は他ツール向けの入力データで assertion を持たないことが仕様であり、その directory だけ検査を緩めたい。project 全体で `testAssertion` を切ると、fixture 以外の実テストでも同じ rule が緩む。

`rules` は toggle 1 段の構成で、path 単位の粒度を持たない。`overrides` を追加し、glob で範囲を絞った上で toggle を重ねられるようにする。

## Decision Drivers

- ESLint の `overrides` は AI agent と人間レビュアーの双方が既に知っているメンタルモデル。新しい配列/merge semantics を発明せず、それに倣うことで学習コストを増やさない
- glob の `*` が `/` を跨ぐ globset のデフォルト挙動は、`src/*.ts` が `src/api/db.ts` にまで意図せず一致し、ESLint の `overrides.files` に慣れた利用者の直感と食い違う
- `.guardrails.json` 自体の trust boundary (git root 直下) を再利用できる範囲と、entry 単位の glob compile という新しい失敗点が生まれる範囲を分けて扱う必要がある
- 1 toggle が複数 `rule_id` を束ねる既存の粒度 (`security` は 2 個、`astSecurity` は 15 行のうち 14 個、README `Security Rules`/`AST Security Rules` 参照) は override 導入でも変えない。誰も要求していない細分化は追加しない (YAGNI)

## Considered Options

- A. ESLint 風 `overrides` 配列。`files` glob と `rules` の部分オブジェクトをペアで持ち、entry 単位で key-wise merge (採用)
- B. path prefix ごとに別の `.guardrails.json` を置く (per-directory config file)
- C. `rules` の値を `bool` でなく `{ enabled: bool, exclude: string[] }` に拡張し、toggle 自身に除外パスを持たせる
- D. glob でなく正規表現で path をマッチさせる

## Decision Outcome

採用: **Option A**。`src/config.rs` の `OverrideEntry { files: Vec<GlobMatcher>, rules: ProjectRulesConfig }` が `.guardrails.json` の `overrides` 配列を保持する。`Config::effective_rules_with_notes` が対象 file の git-root 相対パスに対して各 entry を配列順に評価し、マッチした entry の `rules` を base の `RulesConfig` へ `RulesConfig::apply_overrides` (rule key 単位の merge) で重ねる。同じ rule key を複数 entry が指定したときは、後方の entry が勝つ。ESLint の `overrides` と同じく、entry 全体の置換ではなくキー単位の merge である。

glob は `GlobBuilder::literal_separator(true)` で compile する。default の `false` は `*` が `/` を跨ぐため、`src/*.ts` が `src/api/db.ts` にまで一致してしまい、ESLint の `overrides.files` が前提とする「ディレクトリ境界を越えない」直感と食い違う。

マッチ対象は絶対パスでも cwd 相対パスでもなく、常に git root からの相対パスに正規化した文字列である。`..` で git root の外へ出る `file_path` はどの override にもマッチしない (path-traversal boundary の再利用)。

override の `rules` キーは top-level `rules` と同じ toggle 名であり、`rule_id` ではない。1 toggle が複数 `rule_id` を束ねる既存の粒度は override でも変わらないため、path 単位で `astSecurity` を切ると、その path に属する 14 個の `rule_id` (`child-process-injection`、`err-stack-exposure`、`postmessage-origin-missing` 等、README `AST Security Rules` 参照) が丸ごと切れる。同様に `security` を切ると `security`/`dangerous-inner-html` の 2 個の `rule_id` が同時に切れる。1 個の `rule_id` だけを path 単位で切る手段はない。

override がマッチした file で rule を無効化すると、`effective_rules_with_notes` が無効化した rule 名とマッチした pattern を記した note を積む (例: `override disabled rule(s) [testAssertion] for pattern(s) [src/**/*.test.ts]`)。hook はこの note を `resolve_effective_rules_with_notes` (`src/hook.rs`) で JSON envelope の `notes` と stderr の両方に流す。

`overrides` entry の `files` に compile できない glob pattern があると、`Config::compile_override_entry` はその entry を丸ごと `Err` で返し、`Config::merge` が失敗した pattern を `Config::invalid_override_patterns` へ集約する。`effective_rules_with_notes` は呼び出しのたびに (対象 file がどの entry にもマッチしなくても) `invalid_override_patterns` の各 pattern について `override entry dropped: glob pattern "..." failed to compile` という note を積む。この note も同じ `resolve_effective_rules_with_notes` 経路で JSON envelope の `notes` と stderr に流れる。

### `overrides` の entry 単位 glob 失敗は ADR-0004 の config エラー軸と別軸

ADR-0004 の「config エラー」軸 (fail-open with defaults、`Config::with_project_overrides` が `ConfigError::Parse` を返し `Config::default()` で続行) が扱うのは `.guardrails.json` 自体の JSON parse 失敗、つまり file 全体が壊れているケースである。

両者を分けるのは fallback の及ぶ範囲である。file 全体が壊れていれば読める設定が 1 つも無いので defaults へ倒すしかないが、glob 1 個が compile できないだけなら壊れた entry を外して残りを生かせる。

| 失敗の軸                       | fallback の範囲                                                 |
| ------------------------------ | --------------------------------------------------------------- |
| `.guardrails.json` の parse    | config 全体を `Config::default()` へ (fail-open)                |
| `overrides` entry の glob      | 当該 entry のみ drop、他 entry と `rules` は保持 (fail-partial) |

entry 単位の失敗は `Config::compile_override_entry` (`src/config.rs`) が `Result::Err(Vec<String>)` で失敗した pattern 文字列を返すことで閉じ込める。`Config::merge` は当該 entry を drop し、pattern を `Config::invalid_override_patterns` へ集めて note 化に回す。

### Consequences

- Good: rule 適用の粒度が project 全体から path 単位に上がる。fixture directory やレガシー directory など、特定範囲だけ toggle を緩められる
- Good: ESLint の `overrides` に倣うことで、AI agent も人間も新しい merge semantics を新たに覚えずに使える
- Good: override が rule を無効化したときは note で可視化されるため、AI agent は「なぜこの rule が発火しなかったか」を追える (`src/hook/tests.rs` で pin 済み)
- Good: entry 単位の glob compile 失敗が config 全体を defaults に倒さない。1 entry の typo が project 全体の override を無効化しない
- Good: `files` の pattern が glob として compile できない entry は drop と同時に note が積まれる。`tests/cli/config.rs` の T-464 (`compile_できない_globを書いたconfigではnoteがjson_envelopeに出る`) がこの挙動を pin している
- Bad: override の `rules` キーは top-level と同じ粗さの toggle であり、`rule_id` 単位の細かい制御はできない。`astSecurity` を 1 path で切ると 14 個の `rule_id` が切れる。`AST Security Rules` の表は 15 行あり、残る 1 個の `excessive-nesting` は override で切れない
- Bad: override 解決は `file_path` ごとに毎回 entry を線形走査する。entry 数が多い project では、rule 判定の前に glob match のコストが積み上がる
- Bad: symlink 経由の repository root では override が効かない。`current_dir` が root を実体パスへ解決する一方、agent が送る `file_path` は解決されないため `strip_prefix` が外れる。rule が有効なまま残る fail-closed 方向だが、利用者が書いた override は無視される。`~/GitHub/...` 形式の root は影響を受けず、動機となった dotclaude もそこに入る。相対化できなかったことは note に出る (`override matching skipped: ...`)。`file_path` 側を canonicalize する対応は backlog。設計から起こす必要はなく、`src/invariant.rs` の `canonical_path` (親を canonicalize して file 名を再結合) と `canonical_relative_key` が同じ caller context で既に解いている。統合時は両者の fallback が違う点に注意する。invariant 側は raw path で `strip_prefix` し直すが、それは `..` を畳み込まないため override に持ち込むと traversal 対策が緩む

### Verification

- `src/config/tests.rs` で、`overrides` 未指定時は空のまま読めること、`files`/`rules` を保持すること、compile 不能な glob を含む entry だけが drop され他 entry と基底 `rules` は影響を受けないこと、pattern 一致/不一致で toggle が変わる/変わらないこと、同じ rule key を複数 entry が指定したときは後方が勝つこと、別 rule key は消えないこと、`..` で root の外に出る path はどの override にもマッチしないこと、`src/*.ts` が `src/api/db.ts` にマッチしないこと、絶対パスの pattern は git-root 相対のマッチ対象に一致しないこと、相対パスの `file_path` は git root へ join してから同じ override が当たること、filesystem root を越える `..` で始まる絶対 `file_path` はどの override にもマッチしないことを assert
- `src/hook/tests.rs` で、override が registry 経由の rule (`sensitive-file`) と registry 外で gate される rule (`ast_security` 経由の `child-process-injection`) の両方を止めること、override が rule を無効化すると note に無効化した rule 名とマッチした pattern が乗ることを assert
- `tests/cli/config.rs` で実バイナリを通し、`overrides` の対象パスへの Write は exit 0 で通り、対象外パスへの同じ content は exit 2 で block されることを assert。同じファイルの T-464 は compile 不能 glob を書いた config で JSON envelope の `notes` に当該 pattern を含む note が乗ることを assert し、green
