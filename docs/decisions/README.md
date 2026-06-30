# Architecture Decision Records

This directory contains important decisions about the project's architecture.

## ADR List

| Number | Title | Status | Date |
|--------|-------|--------|------|
| [0001](0001-adopt-installsh-prefetch-for-oxlint-provisioning.md) | Adopt install.sh prefetch for oxlint provisioning | accepted | 2026-05-08 |
| [0002](0002-publish-release-binaries-via-orphan-branch-mirror.md) | Publish release binaries to sentinels via orphan-branch mirror | accepted | 2026-05-13 |
| [0003](0003-math-random-severity-policy.md) | Math.random ルールの severity policy | accepted | 2026-05-14 |
| [0004](0004-fail-mode-policy.md) | Fail-mode policy | accepted | 2026-05-14 |
| [0005](0005-json-envelope-and-sysexits-adoption.md) | JSON envelope と sysexits exit code の採用 | accepted | 2026-05-14 |
| [0006](0006-legacy-config-migration-policy.md) | Config file search policy | accepted | 2026-05-20 |
| [0007](0007-post-edit-content-resolution-and-degradation-contract.md) | Post-edit content resolution と degradation contract | accepted | 2026-05-14 |
| [0008](0008-unsafe-html-injection-rule-id-separation.md) | ast_security 配下の innerHTML / document.write を unsafe-html-injection に分離 | accepted | 2026-05-14 |
| [0009](0009-custom-rule-overlap-eval.md) | eval 検出を custom AST rule に集約し oxlint の同等 rule を抑止する | accepted | 2026-05-17 |
| [0010](0010-reporter-output-design-intent.md) | reporter stderr の `━` 装飾と anti-circumvention 文言を維持する | accepted | 2026-05-17 |
| [0011](0011-column-not-needed-fix-snippet-suffices.md) | 同一行複数違反では column 番号を出力せず fix message snippet で対象を特定する | accepted | 2026-05-17 |
| [0012](0012-ssr-target-scope-pages-router-and-use-server.md) | SSR target detection は Pages Router の `getServerSideProps` と `'use server'` directive に限定し App Router route handler / Remix loader,action は対象外とする | accepted | 2026-05-17 |
| [0013](0013-client-env-allow-list-and-nextjs-prefix.md) | `client-env-public-leak` は allow-list 哲学を採用し Next.js `NEXT_PUBLIC_` prefix を一級扱い、Vite/CRA/Storybook prefix は延期する | accepted | 2026-05-17 |
| [0014](0014-ssr-secret-bleed-shape-based-carve-outs.md) | `ssr-secret-bleed` は shape-based 検出を採用し、spread / 変数バインディング / dynamic getter は 1-file 静的解析制約により intentional carve-out として記録する | accepted | 2026-05-17 |
| [0015](0015-cot-leakage-marker-design.md) | `cot-leakage-marker` rule の marker 選定 / self-exclusion / Windows path normalize の方針 | accepted | 2026-05-17 |
| [0016](0016-framework-coverage-axis-nextjs-api-middleware.md) | Server-side rule の scope は Next.js `app/api` + `pages/api` + `middleware` に揃え、shared regex pool 経由で統一する | accepted | 2026-05-17 |
| [0017](0017-hook-must-not-create-tools-json.md) | Hook 起動時に `.claude/tools.json` を自動生成しない (hint stderr 出力のみ) | accepted | 2026-05-19 |
| [0018](0018-severity-ord-and-block-threshold.md) | Introduce `Ord` on `Severity` and replace the `block_on` set with `block_threshold` | accepted | 2026-05-26 |
| [0019](0019-precision-measurement-harness.md) | Measure per-rule precision, recall, and latency with an in-source corpus harness | accepted | 2026-06-10 |
| [0020](0020-diff-aware-demotion-of-preexisting-violations.md) | Demote preexisting violations to advisory via lazy two-pass diff-aware classification | accepted | 2026-06-10 |
| [0021](0021-isolate-ast-structural-rule-overflow-via-subprocess-re-exec.md) | Isolate AST structural-rule overflow in a re-exec subprocess and read signal-death as a block | accepted | 2026-06-17 |
| [0022](0022-keep-security-fix-messages-opaque-to-the-matched-construct.md) | Keep security and guard fix messages opaque to the matched construct | accepted | 2026-06-17 |
| [0023](0023-stateless-path-consistent-semantic-invariant-gate.md) | Keep the semantic invariant gate stateless and path-consistent | accepted | 2026-06-24 |
| [0024](0024-test-assertion-quality-expect-chain-scope-contract.md) | Scope test-assertion quality grading to expect() chains, redeemed by any real assertion | accepted | 2026-06-24 |
| [0025](0025-adopt-a-source-masking-policy-for-the-scan-pipeline.md) | Mask comments but preserve string literals, and accept the no-regex-literal scanner limitation | accepted | 2026-06-30 |
| [0026](0026-adopt-an-oxlint-download-trust-model.md) | Anchor oxlint download integrity on the SHA-256 pin, not on transport or host | accepted | 2026-06-30 |
| [0027](0027-define-the-hook-ast-pass-fail-mode-policy.md) | Fail open on a benign parse failure, fail closed on an invisible stack overflow | accepted | 2026-06-30 |
| [0028](0028-treat-the-oxlint-rule-name-prefix-as-an-attribution-seam.md) | Use the `oxlint/` rule-name prefix as the violation attribution seam | accepted | 2026-06-30 |
| [0029](0029-do-not-add-walk-fences-to-the-node-modules-bin-resolver.md) | Keep the canonicalize-plus-project-root boundary and add no walk fences to the bin resolver | accepted | 2026-06-30 |
| [0030](0030-treat-rule-id-string-values-as-a-frozen-output-contract.md) | Treat `rule_id` string values as a frozen public output contract | accepted | 2026-06-30 |
| [0031](0031-require-semantic-analysis-must-stay-in-sync-with-scoping-readers.md) | A rule that reads scoping must extend `requires_semantic` and tolerate absent scoping | accepted | 2026-06-30 |

## By Status

### Accepted

- **0001**: Adopt install.sh prefetch for oxlint provisioning
- **0002**: Publish release binaries to sentinels via orphan-branch mirror
- **0003**: Math.random ルールの severity policy
- **0004**: Fail-mode policy
- **0005**: JSON envelope と sysexits exit code の採用
- **0006**: Config file search policy
- **0007**: Post-edit content resolution と degradation contract
- **0008**: ast_security 配下の innerHTML / document.write を unsafe-html-injection に分離
- **0009**: eval 検出を custom AST rule に集約し oxlint の同等 rule を抑止する
- **0010**: reporter stderr の `━` 装飾と anti-circumvention 文言を維持する
- **0011**: 同一行複数違反では column 番号を出力せず fix message snippet で対象を特定する
- **0012**: SSR target detection は Pages Router の `getServerSideProps` と `'use server'` directive に限定し App Router route handler / Remix loader,action は対象外とする
- **0013**: `client-env-public-leak` は allow-list 哲学を採用し Next.js `NEXT_PUBLIC_` prefix を一級扱い、Vite/CRA/Storybook prefix は延期する
- **0014**: `ssr-secret-bleed` は shape-based 検出を採用し、spread / 変数バインディング / dynamic getter は 1-file 静的解析制約により intentional carve-out として記録する
- **0015**: `cot-leakage-marker` rule の marker 選定 / self-exclusion / Windows path normalize の方針
- **0016**: Server-side rule の scope は Next.js `app/api` + `pages/api` + `middleware` に揃え、shared regex pool 経由で統一する
- **0017**: Hook 起動時に `.claude/tools.json` を自動生成しない (hint stderr 出力のみ)
- **0018**: Introduce `Ord` on `Severity` and replace the `block_on` set with `block_threshold`
- **0019**: Measure per-rule precision, recall, and latency with an in-source corpus harness
- **0020**: Demote preexisting violations to advisory via lazy two-pass diff-aware classification
- **0021**: Isolate AST structural-rule overflow in a re-exec subprocess and read signal-death as a block
- **0022**: Keep security and guard fix messages opaque to the matched construct
- **0023**: Keep the semantic invariant gate stateless and path-consistent
- **0024**: Scope test-assertion quality grading to expect() chains, redeemed by any real assertion
- **0025**: Mask comments but preserve string literals, and accept the no-regex-literal scanner limitation
- **0026**: Anchor oxlint download integrity on the SHA-256 pin, not on transport or host
- **0027**: Fail open on a benign parse failure, fail closed on an invisible stack overflow
- **0028**: Use the `oxlint/` rule-name prefix as the violation attribution seam
- **0029**: Keep the canonicalize-plus-project-root boundary and add no walk fences to the bin resolver
- **0030**: Treat `rule_id` string values as a frozen public output contract
- **0031**: A rule that reads scoping must extend `requires_semantic` and tolerate absent scoping

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
- **Superseded**: Replaced by another ADR (e.g. `superseded by ADR-NNNN`)

---

*Last updated: 2026-06-30*
*Auto-generated by: update-index.py*
