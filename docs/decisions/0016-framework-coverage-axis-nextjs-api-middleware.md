---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# Server-side rule の scope は Next.js `app/api` + `pages/api` + `middleware` に揃え、shared regex pool 経由で統一する

## Context and Problem Statement

`src/rules.rs` は file_pattern 用の `LazyLock<Regex>` を 7 個提供する。

| Pattern                     | 正規表現                      | 用途                           |
| --------------------------- | ----------------------------- | ------------------------------ |
| `RE_JS_FILE`                | `\.(tsx?\|jsx?)$`             | JS/TS 全般                     |
| `RE_TEST_FILE`              | `\.(test\|spec)\.[jt]sx?$`    | テストファイル                 |
| `RE_ALL_FILES`              | `.`                           | 全 path                        |
| `RE_REACT_FILE`             | `\.(tsx\|jsx)$`               | React/JSX                      |
| `RE_API_FILE`               | `(^\|/)(app\|pages)/api/`     | Next.js API endpoint           |
| `RE_API_OR_MIDDLEWARE_FILE` | API + `middleware\.[jt]sx?`   | API + Next.js middleware       |
| `RE_API_OR_ROUTE_FILE`      | API + `app/**/route\.[jt]sx?` | API + App Router route handler |

これに依存する rule が 7+ ある (`corsWildcard`, `transaction`, `child-process-injection`, `err-stack-exposure`, `non-literal-fs-path`, `non-literal-require`, 等)。`API_PREFIX_PAT = r"(^|/)(app|pages)/api/"` で Next.js convention に hardcode 結合している。

未文書化の load-bearing decision が 3 つある。

1. **Framework coupling**: Express (`routes/*.js` / `app.get(...)` style) / Fastify / NestJS (`*.controller.ts`) / Hono は **意図的に対象外**。OUTCOME `Non-goals` の「独立した Node.js バックエンドのコード監査」と整合するが、code 上では `API_PREFIX_PAT` が Next.js 結合の事実を黙示するのみ。

2. **Shared pool 規約**: 新規 rule が必要とする file_pattern は **既存 7 pattern からの選択を優先**、新規 inline 禁止。ただし code 上の文書化はゼロ、新規 rule PR で「ad-hoc に inline regex を作る」を防ぐ機構が test だけ。

3. **App Router route.ts の二重扱い**: `RE_API_OR_ROUTE_FILE` は API + route handler 両対象だが、ssr-secret-bleed のような rule は route handler を SSR target に含めない (ADR-0012 で除外)。同じ file が rule によって対象 / 対象外が変わる構造で、user は「どの rule がどの scope か」を README の per-rule 説明から読む必要がある。

これが ADR 化されていないと、(a) Express/NestJS 対応 PR で「shared pool 拡張 vs 新 rule 個別実装」を毎回議論、(b) 新規 rule の file_pattern 選択が ad-hoc 化、(c) route.ts の二重扱いが「Bug or 仕様?」を都度判断する coordinate cost が発生する。

## Decision Drivers

- 7+ rule が共有する file_pattern 設計を ADR で固定し、新規 rule の patten 選択を高速化
- OUTCOME `Non-goals` の「独立した Node.js バックエンド」境界と code の framework coupling の整合性を ADR で明示
- shared pool 規約 (新規 rule は既存 pattern を再利用) を contributor-facing として記録、ad-hoc inline regex の divergence を防止
- README の per-rule scope 記述と ADR の framework coverage 方針を 1 つの起点に集約

## Considered Options

- **A. 現状維持 + ADR 化 (採用)**: Next.js coupling + 7 pattern pool + 新規 inline 禁止規約を ADR で固定
- B. Framework abstraction layer: `FrameworkConvention` trait を導入し Next.js / Express / NestJS を切り替え可能化
- C. Config 化: user が `serverSideFilePatterns` を `.claude/tools.json` で配列指定
- D. ファイル top の magic comment (`// guardrails:server-side`) で各 rule の scope を user 側で明示

## Decision Outcome

採用: **Option A**。Next.js coupling と shared pool 規約を ADR で固定、framework 拡張は本 ADR の supersede / 改訂を伴う運用に揃える。

### Scope

本 ADR は次の境界を固定する。

- `src/rules.rs` の 7 `LazyLock<Regex>` pattern (`RE_JS_FILE` / `RE_TEST_FILE` / `RE_ALL_FILES` / `RE_REACT_FILE` / `RE_API_FILE` / `RE_API_OR_MIDDLEWARE_FILE` / `RE_API_OR_ROUTE_FILE`) を server-side rule の shared pool とする
- `API_PREFIX_PAT = r"(^|/)(app|pages)/api/"` は Next.js Pages Router + App Router API endpoint の convention に hardcode する。Express / NestJS / Hono の routes/ や controller pattern は **意図的に対象外**
- `middleware.{ts,js}` (Next.js Edge / Node middleware) は API と同じ server-side scope に含める
- App Router `app/**/route.ts` は `RE_API_OR_ROUTE_FILE` で API 扱いとする一方、SSR target rule (ADR-0012) では除外する。この二重扱いは意図的 (route handler は Response object 直接返却で client serialization なし)
- 新規 server-side rule が必要とする `file_pattern` (rule applicability 判定) は **既存 7 pattern からの選択を優先**。新規 inline `file_pattern` regex の追加は本 ADR の改訂を伴う
- 本規約の対象は `Rule::file_pattern` (rule の発火 gate) **のみ**。rule 内部の content/path-matching 用 regex (例: `src/rules/generated_file.rs` の `\.generated\.[a-zA-Z]+$`、`src/rules/sensitive_file.rs` の `\.pem$`、`src/rules/http_resource.rs` の `RE_HTTP_URL`、`src/rules/transaction.rs` の `RE_WRITE_OPS`、`src/rules/raw_html.rs` の `RE_HTML_CONCAT` 等) は **本 ADR の scope 外**。これらの inline regex は rule のドメイン語彙そのもので、shared pool に集約する意味がない
- 7 pattern は OUTCOME `Behavior` の「フロントエンドプロジェクト (UI / hook / util / CSS / SSR/SSG の server-side コードを含む)」のうち server-side 側を担う
- Framework abstraction layer (Option B) は YAGNI、現状 caller 実需なし

### Consequences

- Good: 新規 server-side rule の file_pattern 選択が「7 pattern から選ぶ」操作に固定、ad-hoc inline regex の divergence を防ぐ
- Good: Express / NestJS support 要望が来た時、本 ADR の supersede 起点で議論可能 (毎回 PR で再議論しない)
- Good: README の per-rule scope 記述が ADR の framework coverage 方針と 1 起点で対応
- Good: ADR-0012 (SSR target scope) + ADR-0013 (allow-list philosophy) + ADR-0014 (shape-based carve-outs) と 4 つで Next.js コア coverage が完結
- Bad: Express / NestJS / Hono user に対する coverage gap、本 hook の値が下がる (rule の README で「Next.js 中心」を明記)
- Bad: 7 pattern が増えるたび contributor の認知負荷が上がる、新規 pattern 追加 PR では「既存 pattern との重複 / abstractable か」を本 ADR 観点で review
- Bad: `app/**/route.ts` の二重扱いが新規 rule で説明責任を生む

### Confirmation

`src/rules/tests.rs` の `re_api_file_rejects_near_miss_paths` test 等で各 pattern の境界 (positive / near-miss / negative) を assert する。

新規 rule 追加 PR の review checklist:

- 新 rule の file_pattern は 7 shared pool の lookup か?
- shared pool 外の pattern が必要なら本 ADR の改訂 PR を同時提出しているか?

```bash
# Next.js Pages Router API: 検出される
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/src/pages/api/users.ts","content":"import { exec } from \"child_process\"; exec(req.body.cmd);"}}' \
  | ./target/debug/guardrails 2>&1 | cat

# Express routes: 検出されない (意図的)
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/src/routes/users.ts","content":"import { exec } from \"child_process\"; exec(req.body.cmd);"}}' \
  | ./target/debug/guardrails 2>&1 | cat
```

## Pros and Cons of the Options

### A. 現状維持 + ADR 化 (採用)

- Good: 7+ rule が既存 pattern を再利用、divergence を防ぐ
- Good: framework 拡張議論の起点が本 ADR に集約
- Bad: Next.js 以外の framework user に対する coverage gap

### B. Framework abstraction layer

- Good: Express / NestJS / Hono が同じ rule で対応可能
- Bad: trait 設計コスト、framework 別の semantics 差を 1-file 静的解析で吸収するのは困難
- Bad: 現時点で caller 実需が観測されていない (YAGNI)

### C. Config 化

- Good: user 側で柔軟に scope 指定
- Bad: 設定不在で sane default が機能しなくなる
- Bad: shared pool 規約 (再利用優先) が崩れる

### D. Magic comment 方式

- Good: file ごとに明示
- Bad: AI agent が自動的に書ける場所が増えるため、自己回避 (hook を bypass する自身を AI が生成) のリスク

## More Information

### References

- `src/rules.rs` shared pattern pool (`RE_JS_FILE` 〜 `RE_API_OR_ROUTE_FILE` の 7 const)
- `src/rules.rs` `API_PREFIX_PAT`
- `src/rules/tests.rs` `re_api_file_rejects_near_miss_paths` 等 pattern boundary tests
- `README.md` (per-rule scope 記述)
- OUTCOME `.claude/OUTCOME.md` Non-goals 節 (独立 Node.js バックエンド除外)

### Reassessment Triggers

- Express / NestJS / Hono / Fastify user の coverage 要望蓄積
- Next.js が `app/api` / `pages/api` convention を変更
- shared pool 内で 7 → 10+ に膨張、abstraction 必要性発生
- ADR-0012 (SSR target scope) の framework 拡張に伴う本 ADR 改訂
- 同一 `file_pattern` (gate) を必要とする新規 rule が見つかった場合、shared pool への abstraction を議論

### Related ADRs

- ADR-0012: SSR target scope (Pages Router + `'use server'`)
- ADR-0013: client-env-public-leak allow-list philosophy
- ADR-0014: ssr-secret-bleed shape-based carve-outs

## Amendment 2026-06-24: invariant gate の coverage scope は `.json` runtime config

2026-06-24 census で新規 ADR 昇格を見送った判断 (I2) を、本 coverage-axis ADR への amendment として記録する。#359 で追加した semantic invariant gate (`src/invariant.rs`) が本 ADR の coverage 上どこに位置するかを確定する。

invariant gate は frontend runtime config/data の `.json` を対象とする (feature-flag bool, i18n string, design token, public app config)。scope の境界は 2 段で、mechanism と convention を取り違えないことが要点。

| 軸                   | 境界                                                                                                                                                                             | 種別       |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| 拡張子               | `is_structured_config` が `.json` のみ true。YAML / CIDR 等の infra 設定は false で機械的に除外                                                                                  | mechanism  |
| `.json` 内の発火対象 | `.invariants.json` に human が宣言した pin を持つ file だけが検査される                                                                                                          | mechanism  |
| build config の扱い  | tsconfig.json / package.json は `.json` なので `is_structured_config` は true。機械的には除外されず、OUTCOME Non-goals「ビルド設定の監査」に従い human が pin しない運用で外れる | convention |

YAML 対応は後続 increment であり OUTCOME 判断ではない。build config が外れるのは OUTCOME 非対象という convention であって `is_structured_config` の機械的除外ではない。この 2 つを混同すると、後に YAML 対応を足す際の判断や、build config を誤って pin した場合の挙動を読み違える。

### Related (I2)

- `src/invariant.rs` (`is_structured_config`, `run_invariant_pass`, module doc)
- OUTCOME `.claude/OUTCOME.md` Non-goals 節 (ビルド設定の監査、独立 Node.js バックエンド)
- ADR-0007 (content resolution) — `is_structured_config` を `is_js` read gate に OR する seam
- ADR-0023 (stateless path-consistent invariant gate)

## Amendment 2026-06-24: test-endpoint-prod-guard は single-file / fail-open / advisory

2026-06-24 census で新規 ADR 昇格を見送った判断 (R1) を記録する。#358 の `test-endpoint-prod-guard` (`src/analysis/ast_security/test_route_guard.rs`) が本 ADR の server-side route 監査軸の上で取る posture を確定する。

posture は 3 点で、いずれも意図的に弱く据える。

| 性質        | 内容                                                                            | 受容する欠落                                                  |
| ----------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| single-file | hook が受け取る 1 file の content だけで判定。cross-file の import 追跡はしない | test util が別 file 経由で prod route に混ざる false negative |
| fail-open   | 判定不能なら通す。advisory severity に留め block しない                         | in-file でも shape が外れた test endpoint の見落とし          |
| advisory    | Medium severity。ADR-0018 の `block_threshold` を超えず編集を止めない           | 確信度の低い検出で編集サイクルを止めない代わりに強制力なし    |

cross-file FN と in-file blind spot は意図的に受容する。cross-file 解決への昇格や blocking severity への引き上げはしない。理由は本 ADR の framework coverage 方針 (single-file static, 確信度の低い検出は advisory) と整合させ、guardrails の責務境界 (1 file content) を越えないため。block しない方向は ADR-0004 の fail-open 軸、advisory severity は ADR-0018 の `block_threshold` 体系に従う。

### Related (R1)

- `src/analysis/ast_security/test_route_guard.rs` (module doc に single-file / fail-open / advisory の根拠)
- ADR-0004 (fail-mode policy) — 判定不能時 fail-open
- ADR-0018 (`Ord` on `Severity` と `block_threshold`) — advisory は閾値未満で block しない
