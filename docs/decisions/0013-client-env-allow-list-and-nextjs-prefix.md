---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# `client-env-public-leak` は allow-list 哲学を採用し Next.js `NEXT_PUBLIC_` prefix を一級扱い、Vite/CRA/Storybook prefix は延期する

## Context and Problem Statement

`client-env-public-leak` rule (`check_client_env_public_leak` in `src/ast_security.rs`) は `'use client'` 文脈で `process.env.X` の参照を検出し、X が「client bundle に embed されて良い public env」でない限り flag する。

判定は二重免除機構で構成される。

| 機構                                        | 場所                                                   | 対象                                                     |
| ------------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------- |
| `NEXT_PUBLIC_` prefix の `starts_with` 判定 | `NEXT_PUBLIC_PREFIX` const + `check_client_env_public_leak` の prefix check | Next.js 公式の client-exposed env naming convention      |
| `CLIENT_ENV_ALLOW_LIST` 完全一致            | `CLIENT_ENV_ALLOW_LIST` const                          | 長さ 1: `NODE_ENV` のみ (compile-time embed される定数)  |

ここで明示されていない 2 つの policy が code に潜在している。

1. **Allow-list axis 採用**: deny-list (「これは flag、それ以外 pass」) ではなく allow-list (「これらは pass、それ以外 flag」) を採用。新規 env 追加で sane default = noisy になる
2. **Next.js 専有**: Vite (`VITE_` prefix) / Create React App (`REACT_APP_` prefix) / Storybook (`STORYBOOK_` prefix) は未対応。これは bug / TODO ではなく **意図的延期**

OUTCOME `Behavior` は「フロントエンドプロジェクト」を一般化して記述するが、code は Next.js coupling されている。この乖離が ADR で記録されていないと、Vite/CRA 拡張 PR で「allow-list か deny-list か」を再議論する coordinate cost が発生する。

## Decision Drivers

- `client-env-public-leak` は環境変数 (= 機密の入口) を扱うため、新規 entry の default 挙動が誤って permissive にならない安全側設計
- OUTCOME の「フロントエンドプロジェクト」表現と code の Next.js coupling のギャップを ADR で明示する
- 将来 Vite/CRA/Storybook 対応を追加する際の policy 整合性 (allow-list 拡張 vs deny-list 反転) を予約する
- 1-file 静的解析制約下で誤検出が許容可能な範囲に scope を絞る

## Considered Options

- **A. allow-list philosophy + Next.js prefix (採用)**: `CLIENT_ENV_ALLOW_LIST` + `NEXT_PUBLIC_` prefix の二重免除、それ以外 flag
- B. Deny-list approach: `SENSITIVE_ENV_KEYWORDS` (DB_URL / API_KEY / TOKEN 等) が含まれる場合のみ flag、それ以外 pass
- C. Framework-agnostic prefix expansion: `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` / `STORYBOOK_` 全部を一級対応
- D. Config 化: user が `clientEnvAllowList` / `clientEnvPublicPrefixes` を `.claude/tools.json` で設定

## Decision Outcome

採用: **Option A**。allow-list axis + Next.js prefix 一級対応 + 他 framework prefix の意図的延期。Vite/CRA/Storybook 対応追加時は本 ADR の supersede / 改訂で扱う。

### Scope

本 ADR は次の境界を固定する。

- `CLIENT_ENV_ALLOW_LIST` は allow-list axis を維持する。新規 entry 追加は本 ADR 改訂を伴う (deny-list への反転は supersede が必要)
- `NEXT_PUBLIC_` prefix は `starts_with` で一級対応、`CLIENT_ENV_ALLOW_LIST` とは並走の二機構
- `NODE_ENV` のみ allow-list に含める。React / Next.js / Webpack が compile-time embed する公式 public 値であるため
- Vite (`VITE_`) / CRA (`REACT_APP_`) / Storybook (`STORYBOOK_`) prefix は **現状未対応**、追加時は本 ADR 改訂を伴う
- `process.env.X` の検出は `StaticMemberExpression` の exact shape のみ (bracket access / globalThis / destructured assignment / `process["env"]` は対象外)。これは別 cluster (Cluster Q / V) の検出範囲との一貫性

### Consequences

- Good: 新規 env を `'use client'` で参照しても sane default = flag、user は明示的に allow に追加する operation で安全側
- Good: allow-list 拡張 / deny-list 反転の policy 反転を ADR で track できる
- Good: Next.js 中心の OUTCOME と code の整合
- Bad: Vite/CRA/Storybook user は本 rule で false positive を被る。回避策として user は `clientEnvPublicLeak: false` で disable または該当 prefix env を `CLIENT_ENV_ALLOW_LIST` 形式の workaround が必要 (config 化未実装)
- Bad: `process.env.X` 以外の env access shape (bracket / globalThis / destructured) は silent skip、false negative が残る

### Confirmation

`tests/integration.rs` および `src/ast_security.rs` 内 unit test で `process.env.NEXT_PUBLIC_API_URL` (pass) / `process.env.NODE_ENV` (pass) / `process.env.SECRET_KEY` (flag) の挙動を assert する。

Vite prefix の挙動を確認:

```bash
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/src/components/Component.tsx","content":"\"use client\";\nconst x = process.env.VITE_API_URL;"}}' \
  | ./target/debug/guardrails 2>&1 | cat
```

現状は `client-env-public-leak` で flag される (`VITE_` prefix 未対応のため)。これは known false positive で本 ADR の対象外。

## Pros and Cons of the Options

### A. allow-list philosophy + Next.js prefix (採用)

- Good: 安全側 default (新規 env は flag、明示 opt-out が必要)
- Good: Next.js 中心 OUTCOME と一貫
- Bad: 他 framework user に対する false positive

### B. Deny-list approach

- Good: 既存 secret naming convention を活用 (`SENSITIVE_ENV_KEYWORDS` 再利用)
- Bad: 新規 secret env naming が deny-list に未追加だと silent pass、false negative が増える
- Bad: 安全側 default を破る

### C. Framework-agnostic prefix expansion

- Good: Vite/CRA/Storybook user の false positive 解消
- Bad: framework ごとの prefix convention が変動 (Astro `PUBLIC_` / Nuxt `NUXT_PUBLIC_` / etc.) で常時メンテが発生
- Bad: prefix で許容を判定するため、framework-specific でない user の env (`PUBLIC_*` 等) と衝突

### D. Config 化

- Good: 各 framework / project の事情を user が自分で記述可能
- Bad: config 設定の defaults が偏ると user が `'use client'` 環境で全部 disable する逃げ道を取る
- Bad: 本 audit 時点で config schema 拡張の caller 実需が観測されていない (YAGNI)

## More Information

### References

- `src/ast_security.rs` `CLIENT_ENV_ALLOW_LIST`
- `src/ast_security.rs` `check_client_env_public_leak`
- `src/ast_security.rs` `process_env_access_name_from_sme` (StaticMemberExpression exact shape)
- OUTCOME `.claude/OUTCOME.md` Behavior 節

### Reassessment Triggers

- Vite/CRA/Storybook user の false positive 報告蓄積
- Next.js の `NEXT_PUBLIC_` convention 変更 (Next.js 公式 deprecation 等)
- `process.env.X` 以外の env access shape (bracket / destructured) で実害事例
- ADR-0012 (SSR target scope) と framework 拡張のタイミング同期が必要になった場合

### Related ADRs

- ADR-0012: SSR target scope (Pages Router + `'use server'`)
- ADR-0014: ssr-secret-bleed shape-based carve-outs
- ADR-0016: framework coverage axis (Next.js app/api + pages/api + middleware)
