[English](README.md) | **日本語**

# Architecture Decision Records

このディレクトリにはプロジェクトのアーキテクチャに関する重要な決定事項が記録されている。

## ADR 一覧

| 番号                                                                        | タイトル                                                                                                                                                        | ステータス | 日付       |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------- |
| [0001](0001-adopt-installsh-prefetch-for-oxlint-provisioning.md)            | Adopt install.sh prefetch for oxlint provisioning                                                                                                               | accepted   | 2026-05-08 |
| [0002](0002-publish-release-binaries-via-orphan-branch-mirror.md)           | Publish release binaries to sentinels via orphan-branch mirror                                                                                                  | accepted   | 2026-05-13 |
| [0003](0003-math-random-severity-policy.md)                                 | Math.random ルールの severity policy                                                                                                                            | accepted   | 2026-05-14 |
| [0004](0004-fail-mode-policy.md)                                            | Fail-mode policy                                                                                                                                                | accepted   | 2026-05-14 |
| [0005](0005-json-envelope-and-sysexits-adoption.md)                         | JSON envelope と sysexits exit code の採用                                                                                                                      | accepted   | 2026-05-14 |
| [0006](0006-legacy-config-migration-policy.md)                              | Legacy config migration policy                                                                                                                                  | accepted   | 2026-05-14 |
| [0007](0007-post-edit-content-resolution-and-degradation-contract.md)       | Post-edit content resolution と degradation contract                                                                                                            | accepted   | 2026-05-14 |
| [0008](0008-unsafe-html-injection-rule-id-separation.md)                    | ast_security 配下の innerHTML / document.write を unsafe-html-injection に分離                                                                                  | accepted   | 2026-05-14 |
| [0009](0009-custom-rule-overlap-eval.md)                                    | eval 検出を custom AST rule に集約し oxlint の同等 rule を抑止する                                                                                              | accepted   | 2026-05-17 |
| [0010](0010-reporter-output-design-intent.md)                               | reporter stderr の `━` 装飾と anti-circumvention 文言を維持する                                                                                                 | accepted   | 2026-05-17 |
| [0011](0011-column-not-needed-fix-snippet-suffices.md)                      | 同一行複数違反では column 番号を出力せず fix message snippet で対象を特定する                                                                                   | accepted   | 2026-05-17 |
| [0012](0012-ssr-target-scope-pages-router-and-use-server.md)                | SSR target detection は Pages Router の `getServerSideProps` と `'use server'` directive に限定し App Router route handler / Remix loader,action は対象外とする | accepted   | 2026-05-17 |
| [0013](0013-client-env-allow-list-and-nextjs-prefix.md)                     | `client-env-public-leak` は allow-list 哲学を採用し Next.js `NEXT_PUBLIC_` prefix を一級扱い、Vite/CRA/Storybook prefix は延期する                              | accepted   | 2026-05-17 |
| [0014](0014-ssr-secret-bleed-shape-based-carve-outs.md)                     | `ssr-secret-bleed` は shape-based 検出を採用し、spread / 変数バインディング / dynamic getter は 1-file 静的解析制約により intentional carve-out として記録する  | accepted   | 2026-05-17 |
| [0015](0015-cot-leakage-marker-design.md)                                   | `cot-leakage-marker` rule の marker 選定 / self-exclusion / Windows path normalize の方針                                                                       | accepted   | 2026-05-17 |
| [0016](0016-framework-coverage-axis-nextjs-api-middleware.md)               | Server-side rule の scope は Next.js `app/api` + `pages/api` + `middleware` に揃え、shared regex pool 経由で統一する                                            | accepted   | 2026-05-17 |
| [0017](0017-hook-must-not-create-tools-json.md)                             | Hook 起動時に `.claude/tools.json` を自動生成しない (hint stderr 出力のみ)                                                                                      | accepted   | 2026-05-19 |
| [0018](0018-severity-ord-and-block-threshold.md)                            | Introduce `Ord` on `Severity` and replace the `block_on` set with `block_threshold`                                                                             | accepted   | 2026-05-26 |
| [0019](0019-precision-measurement-harness.md)                               | in-source corpus harness で rule 別 precision / recall / latency を計測する                                                                                     | accepted   | 2026-06-10 |
| [0020](0020-diff-aware-demotion-of-preexisting-violations.md)               | 既存違反を lazy two-pass diff-aware 分類で advisory に降格する                                                                                                  | accepted   | 2026-06-10 |
| [0021](0021-isolate-ast-structural-rule-overflow-via-subprocess-re-exec.md) | AST 構造ルールの overflow を re-exec subprocess で隔離し signal-death を block として読む                                                                       | accepted   | 2026-06-17 |
| [0022](0022-keep-security-fix-messages-opaque-to-the-matched-construct.md)  | security / guard の fix message は matched construct を名指さない                                                                                               | accepted   | 2026-06-17 |

## MADR フォーマットについて

本プロジェクトでは [MADR (Markdown Any Decision Records)](https://adr.github.io/madr/) v4 を採用している。

### ADR の作成方法

```bash
/adr "Decision Title"
```

### ステータスの意味

- **Proposed**: レビュー待ち
- **Accepted**: 承認済み、実装中または完了
- **Rejected**: 検討したが採用しない
- **Deprecated**: 後継 ADR なしで廃止
- **Superseded**: 別 ADR で置き換え (例: `superseded by ADR-0042`)

### Authoring Convention

ADR Decision 本文の code 引用は **関数名 / const 名 / test 関数名** ベースで書く。`file:line` 形式の line ref は使わない (code 進化と共に陳腐化するため)。

| OK                                                                       | NG                                                   |
| ------------------------------------------------------------------------ | ---------------------------------------------------- |
| `src/analysis/ast_security/ssr_env.rs` の `check_client_env_public_leak` | `src/analysis/ast_security/ssr_env.rs:81-103`        |
| `CLIENT_ENV_ALLOW_LIST` const                                            | `src/analysis/ast_security/ssr_env.rs:25`            |
| `ssr_secret_bleed_silent_in_named_function_other_than_gssp` test         | `src/analysis/ast_security/ssr_env/tests.rs:368-375` |

ファイル path 自体は記載してよい。symbol 名で uniqueness が確保できない場合のみ補助的に範囲 ref を併記する。

## 言語ポリシー

ADR は bilingual 構造で運用する。

| トラック    | 配置                 | 役割           |
| ----------- | -------------------- | -------------- |
| Canonical   | `docs/decisions/`    | 英語の原本     |
| Translation | `docs/decisions/ja/` | 日本語訳の並列 |

ルートの `README.md` / `README.ja.md` パターンと同じ運用。英語版が source of truth。両者が乖離した場合は英語版を正とする。

### 運用ルール

- 新規 ADR は英語で記述する。日本語訳が必要になったら `ja/` 配下に並列追加する。
- ディレクトリの index (`README.md` / `README.ja.md`) は同期を保つ。
- ADR 0001-0017 は本ポリシー策定前に記述されたもので、別 Issue による遡及英訳まではタイトルと本文を原語のまま維持する。

---

_Last updated: 2026-05-26_
_Auto-generated by: update-index.sh_
