---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# SSR target detection は Pages Router の `getServerSideProps` と `'use server'` directive に限定し App Router route handler / Remix loader,action は対象外とする

## Context and Problem Statement

`ssr-secret-bleed` と `client-env-public-leak` の 2 rule は「サーバ側で構築した値がクライアントに serialize されるかどうか」を判定軸にする。判定には「現在の関数 / モジュールが SSR target か」を解決する必要がある。

`src/ast_security.rs` の `is_ssr_target_function` および `check_program` は次の 3 trigger のみ SSR target として扱う。

| Trigger                                       | 検出条件                                                                                     |
| --------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `getServerSideProps`                          | 関数名一致 (function declaration / const-arrow at function_depth==0 双方)                    |
| Function body に `'use server'` directive     | React Server Components の Server Action 形式                                                |
| Top-level `'use server'` file                 | ファイル全体が Server Actions module、program-scope の export は SSR target として扱う       |

これに対し次は **意図的に対象外**:

| 除外対象                                | 理由                                                                                                       |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `getStaticProps`                        | SSG (build 時実行) のため client bundle に embed されず secret leakage の risk axis が異なる                |
| Next.js App Router `app/**/route.ts`    | Response object を直接返す API endpoint、client への automatic serialization なし (rule は API scope 側で扱う) |
| Remix `loader` / `action`               | 現状 OUTCOME `Behavior` の対象範囲 (Next.js 中心) を超える                                                   |
| SvelteKit `+page.server.ts` `load`      | 同上                                                                                                       |

negative test (`getStaticProps_is_not_in_scope_for_this_rule` in `src/ast_security.rs`) で `getStaticProps` 除外を assert する。

Issue: 上記 trigger 限定および除外の判断は code と test のみに存在し、「なぜ App Router を含めないのか / Remix loader を含めないのか」の policy が記録されていない。新規 framework support 追加 PR で「Remix loader も SSR target に含めるべきでは」という review が周回する coordinate cost が見込まれる。

## Decision Drivers

- ssr-secret-bleed と client-env-public-leak の framework coverage 境界を明示し、新規 rule / framework support 追加時の起点を固定する
- OUTCOME `Behavior` の「フロントエンドプロジェクト (UI / hook / util / CSS / SSR/SSG の server-side コードを含む)」と「Next.js 中心」運用の境界を policy として記録する
- 1-file 静的解析制約 (OUTCOME `Constraints`) 下で safely 検出可能な SSR boundary を選別する
- false positive (未 export `getServerSideProps` を flag) と false negative (App Router route.ts) のトレードオフを明示する

## Considered Options

- **A. 3 trigger 限定 (採用)**: `getServerSideProps` + function-body `'use server'` + top-level `'use server'` file
- B. Pages Router 全 SSR API を対象: `getServerSideProps` / `getInitialProps` / `getStaticProps` 全て検出
- C. Multi-framework coverage: Remix `loader,action` / SvelteKit `+page.server.ts` / Next.js App Router `route.ts` も対象
- D. Directive-only: `'use server'` directive のみで判定、Pages Router 名前ベース判定なし

## Decision Outcome

採用: **Option A**。Pages Router の `getServerSideProps` と `'use server'` directive の 2 axis に絞り、`getStaticProps` / App Router `route.ts` / Remix loader,action は対象外とする。framework coverage 拡張は新 rule 追加 PR ではなく本 ADR の supersede / 改訂で扱う。

### Scope

本 ADR は次の境界を固定する。

- `src/ast_security.rs` の `is_ssr_target_function` は上記 3 trigger に限定する
- `getStaticProps` は SSG なので serialize 経路が異なり、本 ADR 対象外 (`getStaticProps_is_not_in_scope_for_this_rule` test で negative 維持)
- App Router `app/**/route.ts` の `GET` / `POST` 等 handler は Response object 直接返却で client serialization 経路を持たないため対象外
- Remix `loader` / `action`、SvelteKit `+page.server.ts` `load` 等の他 framework は OUTCOME の Next.js 中心運用方針により現状対象外。framework support 追加時は本 ADR を改訂
- 未 export の `getServerSideProps` も flag する (false positive 容認、false negative 抑制を優先)
- `export const getServerSideProps = () => ...` 形式は `function_depth == 0` でのみ SSR target 認定 (HOC / factory wrap は対象外)

### Consequences

- Good: ssr-secret-bleed / client-env-public-leak / 今後追加される SSR boundary rule が同一の SSR target 定義を共有する
- Good: 「なぜ App Router を含めないのか」という contributor の質問に対し本 ADR が answer source になる
- Good: framework coverage 拡張が単一 PR で silent に進まず、必ず ADR 改訂を伴う
- Good: 1-file 静的解析制約下で safely 検出可能な範囲に scope を絞る
- Bad: Remix / SvelteKit / App Router を主に使う user は false negative を被る (rule の説明文に "Pages Router scope" を明記して周知)
- Bad: 未 export の `getServerSideProps` も flag するので、test helper / 内部ユーティリティ命名重複で false positive が出る (rule の `# ignore-rule` directive 等で抑止可能、未実装)

### Confirmation

`src/ast_security.rs` の `getStaticProps_is_not_in_scope_for_this_rule` test が現状の Pages Router 限定方針を assert する。framework coverage 拡張時は本 test を更新 + ADR 改訂をセットで実施する。

`cargo test ssr_target` で SSR target 判定の test suite (3 trigger ごとの positive + negative) を実行可能。

## Pros and Cons of the Options

### A. 3 trigger 限定 (採用)

- Good: 現在 ecosystem の secret leakage CVE 集中地点 (Pages Router) を確実にカバー
- Good: 1-file 静的解析制約下で誤判定リスクが低い
- Good: framework coverage 拡張時の起点が明確
- Bad: Remix / SvelteKit / App Router 主流 user に対する coverage gap

### B. Pages Router 全 SSR API

- Good: `getInitialProps` / `getStaticProps` も検出
- Bad: `getStaticProps` は build 時実行で client bundle 経路が異なるため誤検出 axis を持ち込む

### C. Multi-framework coverage

- Good: Remix / SvelteKit / App Router まで一気通貫
- Bad: framework 別の serialization 仕様差を 1-file 静的解析で正しくモデル化するのは困難
- Bad: OUTCOME の Next.js 中心運用と乖離、rule の説明責任が肥大

### D. Directive-only

- Good: 名前依存を排除、framework 中立
- Bad: `'use server'` 普及前の Pages Router code path がカバーされない

## More Information

### References

- `src/ast_security.rs` `check_program`
- `src/ast_security.rs` `is_ssr_target_function`
- `src/ast_security.rs` `visit_variable_declarator` の const-arrow form gate (`function_depth == 0` + `getServerSideProps` binding 判定)
- `src/ast_security.rs` `getStaticProps_is_not_in_scope_for_this_rule` test (negative for `getStaticProps`)
- `docs/audit/2026-05-17-undocumented-decisions.md` (Cluster O)
- OUTCOME `.claude/OUTCOME.md` Behavior / Non-goals 節

### Reassessment Triggers

- App Router `route.ts` で secret leakage CVE が ecosystem で公知化
- Remix / SvelteKit support 追加の user request 蓄積
- 1-file 静的解析を超える module graph 解析の導入
