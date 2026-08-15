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

override がマッチした file で rule を無効化すると、`effective_rules_with_notes` が無効化した rule 名とマッチした pattern、無効化した toggle が止める `rule_id` 数を記した note を積む (例: `override disabled rule(s) [testAssertion] for pattern(s) [src/**/*.test.ts] (testAssertion: 1 rule_id(s))`)。件数は `rules::toggle_rule_id_count` (`rules::toggle_isolation!` の唯一の対応表から導出) から取り、toggle ごとに並べて合計しない。`security` の `rule_id` は registry 側と `ast_security` 側の両方から出るため、複数 toggle の件数を足すと実際に止まる検査の数を上回る。`oxlint` のように固定 `rule_id` 集合を持たない toggle は数の代わりに external linter と出す。hook はこの note を `resolve_effective_rules_with_notes` (`src/hook.rs`) で JSON envelope の `notes` と stderr の両方に流す。

`overrides` entry の `files` に compile できない glob pattern があると、`Config::compile_override_entry` はその entry を丸ごと `Err` で返し、`Config::merge_capturing_notes` が失敗した pattern を `override entry dropped: glob pattern "..." failed to compile` という note に変換する。この note は `Config::with_project_overrides` が config を読み込むたびに 1 回だけ積まれ、`Config` 自身はこの note を field として保持しない。`effective_rules_with_notes` は `file_path` に依存する note (無効化した rule 名とマッチした pattern、symlink 解決) だけを返し、compile 失敗の note を再度積むことはない。hook 側は読み込み時の note を `load_config_or_note`、file 単位の note を `resolve_effective_rules_with_notes` (いずれも `src/hook.rs`) がそれぞれ受け取り、同じ JSON envelope の `notes` と stderr に流す。

### `overrides` の entry 単位 glob 失敗は ADR-0004 の config エラー軸と別軸

ADR-0004 の「config エラー」軸 (fail-open with defaults、`Config::with_project_overrides` が `ConfigError::Parse` を返し `Config::default()` で続行) が扱うのは `.guardrails.json` 自体の JSON parse 失敗、つまり file 全体が壊れているケースである。

両者を分けるのは fallback の及ぶ範囲である。file 全体が壊れていれば読める設定が 1 つも無いので defaults へ倒すしかないが、glob 1 個が compile できないだけなら壊れた entry を外して残りを生かせる。

| 失敗の軸                    | fallback の範囲                                                 |
| --------------------------- | --------------------------------------------------------------- |
| `.guardrails.json` の parse | config 全体を `Config::default()` へ (fail-open)                |
| `overrides` entry の glob   | 当該 entry のみ drop、他 entry と `rules` は保持 (fail-partial) |

entry 単位の失敗は `Config::compile_override_entry` (`src/config.rs`) が `Result::Err(Vec<String>)` で失敗した pattern 文字列を返すことで閉じ込める。`Config::merge_capturing_notes` は当該 entry を drop し、pattern を note に変換して呼び出し元 (`Config::with_project_overrides`) へ返す。

### Consequences

- Good: rule 適用の粒度が project 全体から path 単位に上がる。fixture directory やレガシー directory など、特定範囲だけ toggle を緩められる
- Good: ESLint の `overrides` に倣うことで、AI agent も人間も新しい merge semantics を新たに覚えずに使える
- Good: override が rule を無効化したときは note で可視化されるため、AI agent は「なぜこの rule が発火しなかったか」を追える (`src/hook/tests.rs` で pin 済み)
- Good: entry 単位の glob compile 失敗が config 全体を defaults に倒さない。1 entry の typo が project 全体の override を無効化しない
- Good: `files` の pattern が glob として compile できない entry は drop と同時に note が積まれる。`tests/cli/config.rs` の T-464 (`compile_できない_globを書いたconfigではnoteがjson_envelopeに出る`) がこの挙動を pin している
- Bad: override の `rules` キーは top-level と同じ粗さの toggle であり、`rule_id` 単位の細かい制御はできない。`astSecurity` を 1 path で切ると 14 個の `rule_id` が切れる。`AST Security Rules` の表は 15 行あり、残る 1 個の `excessive-nesting` は override で切れない
- Bad: override 解決は `file_path` ごとに毎回 entry を線形走査する。entry 数が多い project では、rule 判定の前に glob match のコストが積み上がる
- Good: pattern のマッチは symlink を解決した後のパスに対して行う (#432)。`src/path_resolve.rs` の `resolve_under_root` が、実在するパスは丸ごと canonicalize し、まだ存在しないパスは最も近い実在の祖先まで遡って canonicalize してから残りを再結合する。遡りは git root で打ち切るので、repository の外を stat しない。解決でパスが変わったときは note に出る (`override matching followed a symlink: ...`)
- Bad: hook が判定してから write syscall が走るまでの間に symlink を差し替える競合 (TOCTOU) は塞げない。PreToolUse hook は書き込み前に 1 回しか呼ばれず、symlink の作成自体も Bash 経由なら hook を通らない。この設計が塞ぐのは、1 回の綴りに対する静的な誤マッチに限る
- Bad: repository 内に symlink を置いている利用者は、override の当たり方が変わる。`packages/web/src` が別ディレクトリを指す monorepo では、`packages/web/**` の override が解決後のパスに当たらなくなる。note で気付ける形にしてあるが、config を書き直す必要は残る
- Good: `configGuard` は override の適用対象から外れる (#433)。`RulesConfig::apply_path_overrides` が override 適用後に値を戻すため、`files: ["**"]` で `configGuard: false` を書いた entry があっても設定ファイルへの編集は止まる。`rules` に直接書く無効化は人の判断として残る
- Bad: 設定ファイルへの編集を止められるのは Write/Edit/MultiEdit の経路だけ。guardrails はこの 3 つの tool input しか受け取らないため、Bash 経由の `sed -i` やリダイレクトは rule に到達しない
- Note: `src/invariant.rs` の `canonical_relative_key`/`canonical_path` は同じ問題を別実装で解いたままになっている。統合は backlog。invariant 側の fallback は raw path での `strip_prefix` で、`..` を畳み込まないため override へそのまま持ち込むと traversal 対策が緩む。doc が明記する「raw path 版より厳しくならない」契約も変わるため、契約変更の pin を足したうえで別 PR にする

### Verification

- `src/config/tests.rs` で、`overrides` 未指定時は空のまま読めること、`files`/`rules` を保持すること、compile 不能な glob を含む entry だけが drop され他 entry と基底 `rules` は影響を受けないこと、pattern 一致/不一致で toggle が変わる/変わらないこと、同じ rule key を複数 entry が指定したときは後方が勝つこと、別 rule key は消えないこと、`..` で root の外に出る path はどの override にもマッチしないこと、`src/*.ts` が `src/api/db.ts` にマッチしないこと、絶対パスの pattern は git-root 相対のマッチ対象に一致しないこと、相対パスの `file_path` は git root へ join してから同じ override が当たること、filesystem root を越える `..` で始まる絶対 `file_path` はどの override にもマッチしないことを assert
- `src/config/tests.rs` の T-507〜T-509 で、compile 不能な glob を含む config を `with_overrides_from_root` で読むと戻り値の note にその pattern が乗ること、compile できる glob だけの config では note が空になること、compile 不能な entry だけが落ちて他の entry と基底 `rules` は保たれることを assert。T-510 は同じ config を `effective_rules_with_notes` に渡しても compile 失敗の note が (読み込み時に一度出たにもかかわらず) 再度は乗らないことを assert し、note が読み込み時の 1 回に限られることを pin している
- `src/hook/tests.rs` で、override が registry 経由の rule (`sensitive-file`) と registry 外で gate される rule (`ast_security` 経由の `child-process-injection`) の両方を止めること、override が rule を無効化すると note に無効化した rule 名とマッチした pattern が乗ることを assert。T-511 は `load_config_or_note` から渡った読み込み時の compile 失敗 note を `resolve_effective_rules_with_notes` が重複させないこと、hook 経路を通した note が 1 件のままであることを assert
- `src/path_resolve/tests.rs` で、symlink のディレクトリを含むパスと symlink そのものを指すパスが実体へ解決されること、未作成のディレクトリを含むパスが最寄りの実在祖先まで遡って解決されること、root の外へ出るパスが `None` になることを assert。実装を 2 通り (symlink を辿らない形、親を 1 段だけ canonicalize する形) に壊して落ちることを確認した
- `tests/cli/config.rs` で実バイナリを通し、`overrides` の対象パスへの Write は exit 0 で通り、対象外パスへの同じ content は exit 2 で block されることを assert。対象外へ向く symlink を経由した Write が exit 2 で止まり note が出ることも同じファイルで assert。同じファイルの T-464 は compile 不能 glob を書いた config で JSON envelope の `notes` に当該 pattern を含む note が乗ることを assert し、green
