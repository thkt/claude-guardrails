---
status: "accepted"
date: 2026-08-11
decision-makers: thkt
---

# hook 命名の検出を oxlint の react plugin に委譲し React project に限って有効化する

## Context and Problem Statement

#422 で `NAMING_ISSUES[1]` (行単位 regex による React custom hook の命名検査) を削除して以降、hook 命名の検出はゼロになっている。以下 3 形はいずれも無発火のまま残る。

| 入力 (`/src/hooks/useFetch.ts`)                   | 削除前 | 削除後 |
| ------------------------------------------------- | ------ | ------ |
| `const fetchData = () => useState(0)`             | 無発火 | 無発火 |
| `function fetchData() { useState(null) }`         | 無発火 | 無発火 |
| `const fetchData = () => ({ d: useState(null) })` | 無発火 | 無発火 |

React 公式は「hook を呼ぶ関数は `use` 接頭辞を持つべき」を規範として定め、linter が強制すると明記している。この向きの検出を guardrails が持たない状態が続いている。

oxlint 1.56.0 は `eslint-plugin-react-hooks` の `rules-of-hooks` を移植済みで、上記 3 形すべてに加えて条件分岐内・ループ内の hook 呼び出しと custom hook が custom hook を呼ぶ形まで検出する。ただし 2 つの gate が同時に開かないと発火しない。react plugin は default off で、`rules-of-hooks` の category は `pedantic` である。`--deny react/rules-of-hooks` を単独で渡しても診断ゼロの無言通過になる。

## Decision Drivers

- 行単位 regex は #305 と #422 で二度破綻している。名前は行単位、hook 利用はファイル単位という粒度の食い違いが原因で、三度目の patch は同じ前提の上に乗る
- 自前 AST 実装は component 判定ヒューリスティック (先頭大文字、`memo(...)`/`forwardRef(...)` ラッパ、default export の無名 arrow) を guardrails が所有することになる
- guardrails の対象は React 限定ではなくフロントエンドプロジェクト全般。Vue/Nuxt の composable は `.ts` に住み、`rules-of-hooks` はそれを React Hook と誤認する
- hook は AI の編集ごとに起動するため、判定の追加コストが起動コストに乗る

## Considered Options

- A. `react/rules-of-hooks` に委譲し、React project と判定したときだけ plugin を有効化する (採用)
- B. `react/rules-of-hooks` に委譲し、gate 無しで無条件に有効化する
- C. `analysis::ast` 上で「本体が `use*` を呼ぶ関数は `use*` 命名」を自前実装する
- D. `RE_NON_USE_ARROW` に concise arrow と `function` 宣言の形を足して regex を拡張する

## Decision Outcome

採用: **Option A**。`src/analysis/oxlint.rs` の `build_args` が、編集対象を含む package が react に依存するときに限り `--react-plugin` を emit する。判定は `src/analysis/react_project.rs` が編集対象から祖先を 10 階層まで遡り、最寄りの package.json ただ 1 個の dependencies, devDependencies, peerDependencies を読んで行う。

`react/rules-of-hooks` は `--deny` 直書きではなく `DEFAULT_DENY_RULES` に置く。`config.allow` は `--allow` を出さずこのリストから差し引くだけなので、直書きすると利用者に無効化手段が残らない。

plugin が道連れに有効化する `react/exhaustive-deps` は `--allow` で抑止する。実測で 671 files 中 71 件の診断のうち 69 件をこの 1 本が占める。抑止は `--deny` ループより前に置く。oxlint は rule 同士では last-wins なので、後ろに置くと利用者自身の `oxlint.deny` を上書きしてしまう。

### Scope

本 ADR は `react/rules-of-hooks` 1 件と、それを発火させるために必要な `--react-plugin` の有効化を対象とする。plugin が同時に有効化する残り 17 個の react correctness rule は、いずれも oxlint が `warning` として返し `Severity::Medium` にマップされるため default の `block_threshold` (`Severity::High`) では編集を止めない。個別の採否判断は行わない。

`block_threshold` を Medium に下げている利用者では、これら 17 個も blocking に変わる。advisory 止まりは default 設定に限った性質である。

### Consequences

- Good: 削除された 3 形に加え、条件分岐内・ループ内の呼び出しと custom hook が custom hook を呼ぶ形まで検出範囲が広がる
- Good: ディレクトリ位置を根拠にした guardrails 独自の規約が消える。React は hook の同一性を関数名と本体の中身だけで定義しており、`hooks/` の位置には言及していない
- Good: `severity: "error"` → `Severity::High` にマップされるため blocking が維持される
- Good: Vue/Nuxt/Svelte のプロジェクトでは plugin が有効化されず、composable が React Hook と誤認されない
- Bad: guardrails の baseline が default off の oxlint plugin に依存する。project-local に置かれた別バージョンの oxlint が `--react-plugin` を受け付けないと exit 1 で JSON を返さず、`rules-of-hooks` だけでなく既存の oxlint 診断も全て消える。unit test では捕まらないので end-to-end で守る
- Bad: React project の判定に package.json の読み取りが 1 回加わる。最寄りの 1 個で打ち切るため走査は編集対象の階層数までで、10 階層で上限に当たる
- Bad: stderr に出る id (`oxlint/eslint-plugin-react-hooks(rules-of-hooks)`) と、無効化のため config に書く key (`react/rules-of-hooks`) が別文字列になる。表示から無効化手順へ辿る道が無いため README に明記する
- Bad: oxlint が返す message は arrow 形の関数を `in function "Anonymous"` と呼ぶ。そのまま流すと agent が存在しない名前を改名しようとするため、この rule に限り fix 文を差し替える

### Verification

- `src/analysis/react_project.rs` の unit test で、最寄りの package.json が react を宣言するとき true、宣言しないとき上位に react があっても false、10 階層以内に package.json が無いとき false、devDependencies/peerDependencies のみでも true を assert
- `src/analysis/oxlint.rs` の unit test で、React project のとき `--react-plugin` が出て非 React project では出ないこと、`oxlint.allow` に `react/rules-of-hooks` を書くと `--deny` が消えること、`--allow react/exhaustive-deps` が最初の `--deny` より前に出ることを assert
- `src/analysis/oxlint.rs` の unit test で、`rules-of-hooks` の fix 文が `Anonymous` を含まないこと、行番号が `Outer function` ラベルから採られること、他 rule では `labels[0]` と help/message の fallback が変わらないことを assert
- `tests/rule_smoke.rs` で、React project 配下の 3 形が実バイナリで報告されること、react 非依存のプロジェクトでは同じコードが無音であること、react plugin を足した同一実行で `eslint/no-console` も報告されることを assert。最後の 1 本が、未知フラグによる全診断消失を捕まえる唯一の経路
