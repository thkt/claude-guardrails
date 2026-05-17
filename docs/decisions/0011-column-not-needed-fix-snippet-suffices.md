---
status: "accepted"
date: 2026-05-17
decision-makers: thkt
---

# 同一行複数違反では column 番号を出力せず fix message snippet で対象を特定する

## Context and Problem Statement

`/tmp/multi.tsx:1` に `eval` + `open-redirect` + `unsafe-html-injection` 3 ルールが同一行発火するケースで、`file:line` だけだと AI が「どの token に対する指摘か」を再 grep する必要があるのではないか、という懸念が Issue #126 Q2 で提起された。後続調査として Issue #131 で実害確認を実施し、結論を本 ADR に固定する。

実害確認の手順と結果は次のとおり。

1. **再現テスト**: 3 ルール同居の最小 ts content を `printf | guardrails` で発火させ、生 stderr を観察した。各違反の fix message に inline snippet が含まれ (`textContent` / `ALLOWED_PATHS.includes(url)` / `JSON.parse()`)、対象 token と 1:1 で対応していることを確認した
2. **recall 横断検索**: 60 日分・複数キーワード組み合わせで `guardrails` / GitHub プロジェクト横断検索を実施。「同一行複数違反 → AI が誤った順序で fix」の明示的な実利用ログは発見できなかった
3. **歴史的経緯**: Issue #125 (PR #129) で `open-redirect` / `cors-wildcard` / `unsafe-html-injection` の fix message に inline snippet を導入済み。column の役割 (対象 token 特定) を snippet が代替している

## Decision Drivers

- AI agent が再 grep せず違反 → fix の対応を読み取れる (OUTCOME: hook の stderr の指示を読み、人手介入なしで修正を完了する)
- hook 起動コストを増やさない (column 取得は oxc parser から可能だが、JSON envelope / reporter / test fixture の更新コストが連鎖する)
- 既存 fix message 設計 (ADR-0009 / Issue #125) との整合性を保つ
- 仮説の実害が立証されない限り推測ベースで構造を増やさない (YAGNI)

## Considered Options

- A. column 番号を JSON envelope と reporter output に追加する
- **B. 現状維持 (採用)**: `rule_id` + fix message inline snippet で対象 token を特定する

## Decision Outcome

採用: **Option B**。Issue #125 で確立された fix message snippet パターンが column の役割を実質的に代替しているため、column 追加は不要と判断する。実害事例が将来観察されたら、本 ADR を Superseded として更新し column 追加 enhancement を起票する。

### Scope

本 ADR は次の 3 点を固定する。

- `src/reporter.rs` の reporter output に column 番号を追加しない
- `src/rules.rs` の `Violation` struct に `column` フィールドを追加しない
- JSON envelope の `violations[].file`, `violations[].line` のみで対象を表現する

将来 column が必要になるケース (例: 同一行内で同種違反が複数発火し、rule_id だけでは区別不可) は本 ADR の Scope 外とする。

### Consequences

- Good: AI が `rule_id` + fix snippet で対象を一意に特定できる現状の体験を維持する
- Good: oxc parser から column 取得 → `Violation` struct 拡張 → JSON envelope / reporter / test fixture 更新の連鎖コストを払わない
- Good: ADR-0009 (eval 検出集約) と Issue #125 (snippet 具体化) で確立した「fix message が対象を語る」設計線を一貫させる
- Bad: 将来 fix message から snippet が削れるリファクタが入ると column 不在の弱点が再浮上する。本 ADR が「snippet の存在が前提」であることを明示するので、リファクタ時の review で気付ける
- Bad: 同一行内に同種違反が複数 (例: `eval(x); eval(y);`) 発火するケースでは、`file:line` + 同一 rule_id + 同一 fix message の violation が複数並び、AI が同一行内のどの token を直すべきか区別できない。本 ADR は同種重複の救済策には触れず、上記 Scope 節のとおり別 issue で対応する

### Verification

```bash
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/tmp/multi.tsx","content":"eval(x); location.href = redirectUrl; el.innerHTML = userInput;"}}' \
  | ./target/debug/guardrails 2>&1 | cat
```

末尾の `| cat` は ADR-0010 / Issue #130 で導入した stderr の TTY 判定を pipe 側に倒し、ANSI escape を抑止して期待 output と一致させる目的で付与する (terminal 直叩きでは ANSI が残る)。

期待される stderr は次のとおり (header / footer を含む実機出力)。

```
Guardrails ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✗ unsafe-html-injection (guardrails) [HIGH]
    /tmp/multi.tsx:1
    fix: Use el.textContent = x for plain text, or el.innerHTML = DOMPurify.sanitize(x) when HTML is required
  ✗ open-redirect (guardrails) [HIGH]
    /tmp/multi.tsx:1
    fix: Open redirect risk. Validate against an allowlist before redirect (e.g., if (!ALLOWED_PATHS.includes(url)) return).
  ✗ eval (guardrails) [HIGH]
    /tmp/multi.tsx:1
    fix: Avoid eval(). Use JSON.parse() for data or safe alternatives.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BLOCKED: Fix 3 issues in the source code and retry. Do not circumvent this check.
```

各 fix の snippet (`textContent`, `ALLOWED_PATHS.includes(url)`, `JSON.parse()`) が対象 token (`innerHTML`, `location.href`, `eval`) と 1:1 対応する。
