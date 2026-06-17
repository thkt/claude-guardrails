**English** | [日本語](README.ja.md)

# Architecture Decision Records

This directory contains important decisions about the project's architecture.

## ADR List

| Number                                                                      | Title                                                                                                                                                           | Status   | Date       |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ---------- |
| [0001](0001-adopt-installsh-prefetch-for-oxlint-provisioning.md)            | Adopt install.sh prefetch for oxlint provisioning                                                                                                               | accepted | 2026-05-08 |
| [0002](0002-publish-release-binaries-via-orphan-branch-mirror.md)           | Publish release binaries to sentinels via orphan-branch mirror                                                                                                  | accepted | 2026-05-13 |
| [0003](0003-math-random-severity-policy.md)                                 | Math.random ルールの severity policy                                                                                                                            | accepted | 2026-05-14 |
| [0004](0004-fail-mode-policy.md)                                            | Fail-mode policy                                                                                                                                                | accepted | 2026-05-14 |
| [0005](0005-json-envelope-and-sysexits-adoption.md)                         | JSON envelope と sysexits exit code の採用                                                                                                                      | accepted | 2026-05-14 |
| [0006](0006-legacy-config-migration-policy.md)                              | Legacy config migration policy                                                                                                                                  | accepted | 2026-05-14 |
| [0007](0007-post-edit-content-resolution-and-degradation-contract.md)       | Post-edit content resolution と degradation contract                                                                                                            | accepted | 2026-05-14 |
| [0008](0008-unsafe-html-injection-rule-id-separation.md)                    | ast_security 配下の innerHTML / document.write を unsafe-html-injection に分離                                                                                  | accepted | 2026-05-14 |
| [0009](0009-custom-rule-overlap-eval.md)                                    | eval 検出を custom AST rule に集約し oxlint の同等 rule を抑止する                                                                                              | accepted | 2026-05-17 |
| [0010](0010-reporter-output-design-intent.md)                               | reporter stderr の `━` 装飾と anti-circumvention 文言を維持する                                                                                                 | accepted | 2026-05-17 |
| [0011](0011-column-not-needed-fix-snippet-suffices.md)                      | 同一行複数違反では column 番号を出力せず fix message snippet で対象を特定する                                                                                   | accepted | 2026-05-17 |
| [0012](0012-ssr-target-scope-pages-router-and-use-server.md)                | SSR target detection は Pages Router の `getServerSideProps` と `'use server'` directive に限定し App Router route handler / Remix loader,action は対象外とする | accepted | 2026-05-17 |
| [0013](0013-client-env-allow-list-and-nextjs-prefix.md)                     | `client-env-public-leak` は allow-list 哲学を採用し Next.js `NEXT_PUBLIC_` prefix を一級扱い、Vite/CRA/Storybook prefix は延期する                              | accepted | 2026-05-17 |
| [0014](0014-ssr-secret-bleed-shape-based-carve-outs.md)                     | `ssr-secret-bleed` は shape-based 検出を採用し、spread / 変数バインディング / dynamic getter は 1-file 静的解析制約により intentional carve-out として記録する  | accepted | 2026-05-17 |
| [0015](0015-cot-leakage-marker-design.md)                                   | `cot-leakage-marker` rule の marker 選定 / self-exclusion / Windows path normalize の方針                                                                       | accepted | 2026-05-17 |
| [0016](0016-framework-coverage-axis-nextjs-api-middleware.md)               | Server-side rule の scope は Next.js `app/api` + `pages/api` + `middleware` に揃え、shared regex pool 経由で統一する                                            | accepted | 2026-05-17 |
| [0017](0017-hook-must-not-create-tools-json.md)                             | Hook 起動時に `.claude/tools.json` を自動生成しない (hint stderr 出力のみ)                                                                                      | accepted | 2026-05-19 |
| [0018](0018-severity-ord-and-block-threshold.md)                            | Introduce `Ord` on `Severity` and replace the `block_on` set with `block_threshold`                                                                             | accepted | 2026-05-26 |
| [0019](0019-precision-measurement-harness.md)                               | Measure per-rule precision, recall, and latency with an in-source corpus harness                                                                                | accepted | 2026-06-10 |
| [0020](0020-diff-aware-demotion-of-preexisting-violations.md)               | Demote preexisting violations to advisory via lazy two-pass diff-aware classification                                                                           | accepted | 2026-06-10 |
| [0021](0021-isolate-ast-structural-rule-overflow-via-subprocess-re-exec.md) | Isolate AST structural-rule overflow in a re-exec subprocess and read signal-death as a block                                                                   | accepted | 2026-06-17 |
| [0022](0022-keep-security-fix-messages-opaque-to-the-matched-construct.md)  | Keep security and guard fix messages opaque to the matched construct                                                                                            | accepted | 2026-06-17 |

## About MADR Format

This project uses [MADR (Markdown Any Decision Records)](https://adr.github.io/madr/) format, v4.

### How to Create an ADR

```bash
/adr "Decision Title"
```

### Status Meanings

- **Proposed**: Awaiting review
- **Accepted**: Approved, implementing or completed
- **Rejected**: Considered but not adopted
- **Deprecated**: Retired without a replacement ADR
- **Superseded**: Replaced by another ADR (e.g. `superseded by ADR-0042`)

### Authoring Convention

Cite code in ADR Decision bodies by **function name / const name / test name**. Do not use `file:line` references (they go stale as code evolves).

| OK                                                                       | NG                                                   |
| ------------------------------------------------------------------------ | ---------------------------------------------------- |
| `check_client_env_public_leak` in `src/analysis/ast_security/ssr_env.rs` | `src/analysis/ast_security/ssr_env.rs:81-103`        |
| `CLIENT_ENV_ALLOW_LIST` const                                            | `src/analysis/ast_security/ssr_env.rs:25`            |
| `ssr_secret_bleed_silent_in_named_function_other_than_gssp` test         | `src/analysis/ast_security/ssr_env/tests.rs:368-375` |

File paths are fine. Add a range reference only when the symbol name alone is not unique.

## Language Policy

ADRs follow a bilingual structure.

| Track       | Location             | Role             |
| ----------- | -------------------- | ---------------- |
| Canonical   | `docs/decisions/`    | English original |
| Translation | `docs/decisions/ja/` | Japanese mirror  |

This split mirrors the root `README.md` / `README.ja.md` pattern. The English version is the source of truth; if the two diverge, the English version wins.

### Conventions

- New ADRs are authored in English. A Japanese translation under `ja/` is added when a Japanese reader needs it.
- The directory index (`README.md` / `README.ja.md`) is kept in sync.
- ADRs 0001-0017 predate this policy. Titles and bodies stay in their original language until back-translated under separate Issues.

---

_Last updated: 2026-06-17_
_Auto-generated by: update-index.sh_
