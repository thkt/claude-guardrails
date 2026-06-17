---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# `ssr-secret-bleed` は shape-based 検出を採用し、spread / 変数バインディング / dynamic getter は 1-file 静的解析制約により intentional carve-out として記録する

## Context and Problem Statement

`ssr-secret-bleed` rule (`src/analysis/ast_security/ssr_env.rs:105-152`) は SSR target (ADR-0012 で定義) の return statement / object literal を解析し、サーバ専用の secret が client に serialize されるパターンを検出する。

検出は **shape-based**: AST 上で具体的に「secret-named property」または「`process.env.<SENSITIVE>` value」の literal 出現を見つけたときのみ flag する。

| Signal              | 場所                              | 検出対象                                                          |
| ------------------- | --------------------------------- | ----------------------------------------------------------------- |
| key-name (primary)  | `src/analysis/ast_security/ssr_env.rs:132-140`     | `{ secret: ..., token: ..., password: ..., apikey: ..., jwt: ..., credential: ... }` |
| env-value (secondary)| `src/analysis/ast_security/ssr_env.rs:141-149`    | `{ foo: process.env.DB_URL }` 形式の value 側に sensitive env 名が出現 |

これに対し次は **intentional carve-out** (検出しない):

| Carve-out                                | 場所                                      | 理由                                                                                       |
| ---------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------ |
| Spread property: `{ ...env }`            | `src/analysis/ast_security/ssr_env.rs:126-128` (`continue`) | spread 元の object resolution は 1-file 静的解析の範疇外、type info も import 解決も不可   |
| Variable binding: `return data`          | `src/analysis/ast_security/ssr_env.rs:115-119` (doc comment) | `data` の出所 (`fetch().json()` / DB / `process.env.X` 経由)は 1-file では一意に決まらない |
| Dynamic getter: `{ ...getSecret() }`     | (上記 spread と同等)                      | call の戻り値の object literal shape は静的解析で resolve 不能                              |
| Template literal: `` `${process.env.X}` ``| 検出対象外                                | string interpolation は client にレンダリングされるが secret かどうかは型不明              |
| Bracket / destructured env access        | `src/analysis/ast_security/ssr_env.rs:182-190`           | `process.env.X` の exact StaticMemberExpression のみ認識 (ADR-0013 と一貫)                  |

doc comment (`src/analysis/ast_security/ssr_env.rs:115-119`) は spread と var-binding を「intentionally NOT analyzed」と記述するが、`{ props: { ...process.env } }` という known bad pattern が silent に通る理由 (= 1-file 解析制約) と user への influence (= rule で防げない範囲を理解すべき) は明示されていない。

## Decision Drivers

- OUTCOME `Constraints` の「入力は stdin JSON、対象は 1 ファイル分の content」制約から、object graph や module 境界を跨ぐ解析は不可能
- false security の防止: user は rule で **何が捕捉されないか** を理解した上で hook を信頼すべき
- 検出 carve-out の正当化を ADR で固定し、bug report と仕様確認の弁別を容易にする
- 将来 `{ ...process.env }` 形式の literal-spread 検出など、1-file 内で safe に追加可能な改善は本 ADR の scope 外として個別 issue で扱う

## Considered Options

- **A. Shape-based + explicit carve-out 記録 (採用)**: 現状の検出範囲を ADR で固定、carve-out を明示
- B. 緩い heuristic (warning only): spread や var-binding でも `process.env` 単語を含めば advisory として flag
- C. 厳格化 (type-resolver 導入): TypeScript type info を読んで `data` の出所まで追跡
- D. SSR target 全 return を flag (over-detection): SSR target の return は全部 manual review 対象として flag

## Decision Outcome

採用: **Option A**。shape-based の現検出範囲を固定し、carve-out の理由 (1-file 静的解析制約) を ADR で記録する。

### Scope

本 ADR は次の境界を固定する。

- key-name match (`SSR_SECRET_KEYWORDS` 6 entries) を primary signal、`process.env.<SENSITIVE>` value match を secondary signal とする
- nested object literal は再帰検査 (`{ props: { user: { token } } }` も flag)
- spread property (`{ ...x }`) は silent skip、`continue` で次 property へ
- 変数バインディング (`return data`) は解析しない
- dynamic getter (`{ ...getSecret() }`) は解析しない
- template literal の string interpolation は対象外
- `process.env.X` 以外の env access shape (bracket / destructured / globalThis) は対象外 (ADR-0013 と同方針)
- `'use server'` body 内で `check_client_env_public_leak` を抑制 (Server Action body は server 側 context 確定のため、上位 `'use client'` の制約を解除)

### Consequences

- Good: rule の「捕捉範囲」が明示され、user は false security に陥らない
- Good: 1-file 静的解析制約と矛盾する追加検出 (type resolution / module graph) を呼び込まない
- Good: ADR-0012 (SSR target scope) と組み合わせて framework coverage / shape coverage の 2 軸が独立して進化可能
- Bad: `{ props: { ...process.env } }` という known bad pattern は silent に通る (rule fix message / README に scope limitation を明記)
- Bad: 変数経由 (`const data = { token }; return { props: { data } }`) も silent pass
- Bad: 1-file 内で safely 検出可能な spread literal (`{ ...process.env }` の場合) は別 issue として bug fix follow-up

### Confirmation

`tests/rule_smoke.rs` および `src/analysis/ast_security/ssr_env/tests.rs` で次パターンを assert:
- Positive: `{ props: { apiKey: process.env.API_KEY } }` → flag
- Positive: `{ props: { user: { token: "..." } } }` (key-name match) → flag
- Negative (carve-out): `{ ...env }` → no flag (intentional)
- Negative (carve-out): `return data` (variable binding) → no flag (intentional)

```bash
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/src/pages/index.tsx","content":"export async function getServerSideProps() { return { props: { apiKey: process.env.API_KEY } }; }"}}' \
  | ./target/debug/guardrails 2>&1 | cat
```

期待: `ssr-secret-bleed` で flag、severity High。

## Pros and Cons of the Options

### A. Shape-based + explicit carve-out 記録 (採用)

- Good: 1-file 静的解析制約と整合
- Good: rule の boundary が ADR で明示
- Bad: 既知の false negative (spread / var-binding) を許容

### B. 緩い heuristic (advisory)

- Good: false negative の縮小
- Bad: advisory が常時 noise、user が無視するようになる (OUTCOME の「advisory なシグナルを受けたエージェントは作業を中断せず」を逸脱しないが UX 悪化)

### C. 厳格化 (type-resolver 導入)

- Good: false negative 解消
- Bad: hook 起動コスト増、OUTCOME `Constraints` の「起動コストを増やす依存追加は事前に caller 数 / expected scale / performance budget を提示してから議論」を満たさない

### D. SSR target 全 return を flag (over-detection)

- Good: 検出漏れゼロ
- Bad: false positive 過多で rule が disable される運用に直結

## More Information

### References

- `src/analysis/ast_security/ssr_env.rs:31-32` (`SSR_SECRET_KEYWORDS`)
- `src/analysis/ast_security/ssr_env.rs:105-152` (`check_ssr_secret_bleed_return` / `check_ssr_secret_object`)
- `src/analysis/ast_security/ssr_env.rs:115-119` (doc comment with carve-out list)
- `src/analysis/ast_security/ssr_env.rs:126-128` (spread silent skip)
- OUTCOME `.claude/OUTCOME.md` Constraints 節 (1-file content 制約)

### Reassessment Triggers

- `{ ...process.env }` literal-spread 検出 enhancement の bug fix follow-up issue が close
- type-resolver 導入の業界標準化 (oxc / SWC 等で軽量 type info API が安定)
- false negative の実害事例 (CVE / 同種 npm package の incident)

### Related ADRs

- ADR-0012: SSR target scope (Pages Router + `'use server'`)
- ADR-0013: client-env-public-leak allow-list philosophy
- ADR-0016: framework coverage axis (Next.js app/api + pages/api + middleware)
