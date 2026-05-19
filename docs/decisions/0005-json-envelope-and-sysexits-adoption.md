---
status: "accepted"
date: 2026-05-14
decision-makers: thkt
---

# JSON envelope と sysexits exit code の採用

## Context and Problem Statement

guardrails は Claude Code の PreToolUse hook として動作する CLI で、出力経路は (a) stderr に人間/AI 向け human-readable、(b) `--json` 時に stdout に構造化 JSON、(c) terminal exit code の 3 つを持つ。AI agent が hook 結果を機械的に解釈する際、`error.code` (JSON) と exit code (terminal) が同じ分類軸を表裏で表現すれば、retry policy / branch logic / 報告生成を一貫したロジックで書ける。

過去、guardrails は exit code を `0` / `1` のみで運用し、JSON 出力は pre-envelope 形 (`{ violations, decision, exit_code }`) を返していた。これでは:

* AI agent が「input が壊れていた」「panic で内部 error」「lint pass」「lint fail」を exit code から区別できない (全部 1)
* JSON 出力に degradation signal (oxlint 不在等) を載せる場所がない
* hook 入力契約違反と security violation が同じ exit code だと、retry すべきか判断不能

`SuccessEnvelope` / `ErrorEnvelope` shape を導入し、hook protocol (0=allow, 1=advisory, 2=blocking) と sysexits.h を組み合わせた 5 種 exit code 体系に再編する必要があった。同時に prefetch subcommand (oxlint 取得) は hook protocol の外なので別 4 種を採用する mixed scheme になっている。

## Decision Drivers

* AI agent が JSON `error.code` と exit code を 1:1 に解釈できる
* hook protocol (0=allow, 1=advisory, 2=blocking) を破らない
* sysexits.h (BSD 由来) の意味論を活用し、独自数値を増やさない
* prefetch (hook 外サブコマンド) の exit code を hook 用と混同しない
* JSON 出力に degradation signal (oxlint 不在等) を載せる

## Considered Options

* `SuccessEnvelope` + `ErrorEnvelope` + hook 5 種 + prefetch 4 種 (採用)
* pre-envelope 形維持 + exit code は 0/1 のみ
* envelope 導入 + 全 exit code を sysexits.h フル準拠 (9 種以上)
* envelope 導入 + 1 つの exit code 体系で hook と prefetch を兼用

## Decision Outcome

採用: `SuccessEnvelope` + `ErrorEnvelope` の 2 envelope と、hook mode 5 種 + prefetch subcommand 4 種の mixed exit code 体系。

### Envelope shapes

成功時 (`SuccessEnvelope<T>` in `src/envelope.rs`):

```json
{
  "data": { /* command-specific payload */ },
  "degraded": false,
  "notes": []
}
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `data` | object | Yes | command-specific schema は呼び出し側で定義 (hook mode は `data.violations` + `data.decision`) |
| `degraded` | bool | Yes | 機能低下フラグ。oxlint 不在や snippet fallback で `true` |
| `notes` | string[] | Yes | 機能低下の理由・補足。`degraded: true` の時に non-empty。空配列で `degraded: false` を保証 |

エラー時 (`ErrorEnvelope` in `src/envelope.rs`):

```json
{
  "error": {
    "code": "DATA_ERROR",
    "message": "invalid JSON input: ...",
    "next_step": "Pass valid Claude Code hook JSON with tool_name and tool_input fields",
    "retryable": false
  }
}
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `code` | string (enum, SCREAMING_SNAKE_CASE) | Yes | 下表の `JSON error.code` と一致 |
| `message` | string | Yes | 人間向けメッセージ (stderr にも同内容) |
| `next_step` | string | Optional | 次の手 (例: `"Reduce input size"`) |
| `candidates` | string[] | Optional | 修正候補。空なら省略 (`#[serde(skip_serializing_if = "Vec::is_empty")]`) |
| `retryable` | bool | Yes | retry で成功する可能性。現状 false 固定 (hook 入力 / 内部 error は冪等再試行で結果不変) |

### Hook mode exit code (5 種)

`HookExitCode` (`src/hook_exit.rs`) が定義する。`SUCCESS` 経路の violation 有無で 0/1/2 が決まる。

| Exit | Const (`HookExitCode`) | JSON `error.code` | 意味 | Claude Code hook 挙動 |
| --- | --- | --- | --- | --- |
| 0 | `Pass` | (none) | pass — violation なし | allow |
| 1 | `Advisory` | (none) | advisory — `severity.blockOn` 外の violation | warn (AI に stderr 表示、tool 続行) |
| 2 | `Blocking` | (none) | blocking — `severity.blockOn` 内の violation | block (AI に stderr 表示、tool 停止) |
| 64 | `InputError` | `USAGE_ERROR` / `DATA_ERROR` / `IO_ERROR` | hook 入力契約違反 (malformed JSON / oversized payload / stdin read failure / clap parse failure) | block |
| 70 | `Internal` | (envelope なし、stderr のみ) | panic / invariant violation (fail-closed) | block |

### Prefetch subcommand exit code (4 種)

prefetch (`guardrails prefetch`) は hook の外で oxlint 取得を行う。hook protocol の 0/1/2 規約は適用されず、sysexits.h 標準 4 種を使う。

| Exit | JSON `error.code` | 意味 | 発生条件 |
| --- | --- | --- | --- |
| 0 | (none) | 成功 (cache hit または download 成功) | - |
| 64 | (envelope なし) | clap usage error | サブコマンド引数誤り |
| 65 | `DATA_ERROR` | 非対応プラットフォーム | Windows / 非 amd64 など |
| 74 | `IO_ERROR` | network / extract / cache 失敗 | DNS failure / disk full / `XDG_CACHE_HOME` 不在 |

### Mixed scheme の理由

hook mode と prefetch subcommand で exit code 体系が違うのは intentional。

* hook mode (0/1/2/64/70): Claude Code hook protocol が 0/1/2 で挙動分岐するため。1/2 は sysexits.h 外 (convention)、64/70 は sysexits.h 由来。
* prefetch (0/64/65/74): hook の外なので 1/2 を使わない。sysexits.h の `EX_USAGE` / `EX_DATAERR` / `EX_IOERR` を素直に採用。

### sysexits 9 種 → 5 種 / 4 種への縮約根拠

外部 API CLI (scout 等) は sysexits.h 9 種 (`EX_OK` `EX_USAGE` `EX_DATAERR` `EX_NOINPUT` `EX_SOFTWARE` `EX_IOERR` `EX_TEMPFAIL` `GNU TIMEOUT 124` `PJ UNKNOWN 104`) を採用する。guardrails (Hook tool) は次の理由で 5 種に縮約:

| 9 種で採用される code | guardrails で採用するか | 理由 |
| --- | --- | --- |
| `EX_OK` (0) | 採用 (`Pass`) | 共通 |
| `Advisory` (1) | 採用 | hook protocol 由来。sysexits.h には無いが advisory を blocking から分離する用途 |
| `Blocking` (2) | 採用 | hook protocol 由来。blocking を internal error (70) から分離する用途 |
| `EX_USAGE` (64) | 採用 (`InputError`) | hook 入力 JSON 不正を集約 |
| `EX_DATAERR` (65) | 採用しない (hook mode) | hook 入力契約違反は 64 に集約。data error は `error.code` で区別 |
| `EX_NOINPUT` (66) | 採用しない | hook 入力経路では stdin が常に与えられる。`file_path` の存在は exit ではなく envelope で signal |
| `EX_SOFTWARE` (70) | 採用 (`Internal`) | panic / invariant violation |
| `EX_IOERR` (74) | 採用しない (hook mode) | stdin read failure は 64 (input contract) に集約 |
| `EX_TEMPFAIL` (75) | 採用しない | hook は冪等 / retry 前提でない。retry 可能な失敗が出ても次回 hook 起動で同じ判定 |
| `TIMEOUT` (124) | 採用しない | hook は同期短時間処理、timeout は Claude Code 側の `timeout` 設定で管理 |
| `UNKNOWN` (104) | 採用しない | panic に集約 (`Internal` 70) |

prefetch は外部 IO 中心 (download + cache) なので `EX_DATAERR` (65) と `EX_IOERR` (74) を採用する。

### Consequences

* Good, AI agent が JSON `error.code` と exit code を 1:1 で解釈できる
* Good, `degraded: bool` + `notes: string[]` で機能低下を載せる場所が確保される
* Good, hook protocol (0/1/2) と sysexits (64/70) が混在しても call site と test で固定
* Good, prefetch の exit code が hook 用と独立しており、CI script で混同しない
* Bad, hook mode と prefetch で exit code 体系が違うため、`guardrails --help` の after_help 文字列に 2 つの table を書く必要がある (CLI text が公開仕様化)
* Bad, sysexits 9 種フル準拠ではないため、CI/script が scout 等の他 CLI と同じ exit code 解釈を使えない (hook 専用ロジック)
* Bad, 1/2 は sysexits.h に存在しない convention 由来の数値で、新しい読者は出典を `src/hook_exit.rs` doc コメントで確認する必要がある

### Confirmation

envelope schema と exit code は次のテストで pin されている。

| 対象 | テスト |
| --- | --- |
| `SuccessEnvelope` shape | `success_envelope_ok_is_not_degraded` / `success_envelope_with_notes_sets_degraded` / `success_envelope_with_empty_notes_is_not_degraded` (`src/envelope.rs`) |
| `ErrorEnvelope` shape | `error_envelope_wraps_payload_under_error_key` / `error_payload_omits_optional_next_step` / `error_payload_omits_empty_candidates` / `error_payload_includes_present_optional_fields` (`src/envelope.rs`) |
| `error.code` SCREAMING_SNAKE_CASE | `error_code_serializes_screaming_snake_case` (`src/envelope.rs`) |
| `error.code` ↔ sysexits 数値 | `error_code_exit_code_matches_sysexits_h` (`src/envelope.rs`) |
| Hook 5 種 exit code | T-001 `pass_is_zero` / T-002 `advisory_is_one` / T-003 `blocking_is_two` / T-004 `input_error_is_sysexits_usage` / T-005 `internal_is_sysexits_software` (`src/hook_exit.rs`) |
| Hook mode JSON envelope (e2e) | `tests/integration.rs` の `--json` envelope 検証群 |

新規 exit code / envelope field 追加 PR では、上記テストの新規追加または既存 update を description に明示する。

## Pros and Cons of the Options

### envelope 2 種 + hook 5 種 + prefetch 4 種 (採用)

* Good, hook protocol と sysexits.h の両方の意味論を尊重
* Good, AI agent が JSON `error.code` と exit code を 1:1 解釈できる
* Good, prefetch の I/O 失敗を hook 用と分離
* Bad, mixed scheme の説明 (`guardrails --help` after_help) が必要

### pre-envelope 形維持 + exit code 0/1 のみ

* Good, 既存実装変更ゼロ
* Bad, AI agent が input 不正 / panic / lint fail を区別できない
* Bad, degradation signal を載せる場所がない

### sysexits.h フル準拠 (9 種以上)

* Good, scout 等の他 CLI と exit code 解釈を共有できる
* Bad, hook protocol の 1/2 と衝突する (1 は EX_OK の隣で意味不明、2 はそもそも sysexits.h 範囲外)
* Bad, 75 TEMP_FAILURE / 124 TIMEOUT が hook 経路で発生しない (使われない code がノイズ)

### hook と prefetch で 1 つの exit code 体系を兼用

* Good, ドキュメント 1 つで済む
* Bad, prefetch の I/O 失敗 (74) を hook の 1/2 系列と同じ table に書くと、Claude Code が hook output として誤解釈する可能性
* Bad, prefetch で hook protocol の advisory (1) を使うのは意味的に変

## More Information

### Quality Attributes

| Attribute | Priority | Approach |
| --- | --- | --- |
| AI agent API 一貫性 | High | `error.code` ↔ exit code を 1:1、`SuccessEnvelope` + `ErrorEnvelope` の 2 envelope に固定 |
| hook protocol 整合 | High | 0/1/2 を保持、sysexits.h 64/70 を上に積む |
| 拡張性 | Medium | 新 `error.code` 追加は sysexits.h 既存 code から選ぶ、独自数値は増やさない |
| ドキュメント整合 | Medium | `guardrails --help` after_help / README / 本 ADR / `src/hook_exit.rs` doc コメントで同じ table を引用 |

### Trade-offs

| 失う | 得る |
| --- | --- |
| sysexits.h フル準拠ではない (9 種 → 5 種) | hook protocol との整合を維持 |
| hook と prefetch で exit code が違う | hook output として誤解釈されない |
| `Advisory` (1) / `Blocking` (2) は sysexits.h 外 | hook protocol が要求する 3 値分離が保たれる |

### Reassessment Triggers

* `error.retryable: true` を出すべき失敗パスが発生した場合 (例: 外部 secret store fetch を hook 内で行うようになった等)、本 ADR を改訂
* hook mode で 65 `DATA_ERROR` / 74 `IO_ERROR` を envelope の `code` ではなく terminal exit code として区別したい実需が出た場合、5 種拡張を検討
* prefetch が hook protocol の 1/2 を必要とするようになった場合 (現状非該当)、mixed scheme を統一する方向で本 ADR を改訂
* `data` payload schema の変更 (例: `decision` field の値拡張) が出た場合、本 ADR の Envelope shapes セクションを update

### References

* `src/envelope.rs` — `SuccessEnvelope` / `ErrorEnvelope` / `ErrorCode` / `ErrorPayload` 実装
* `src/hook_exit.rs` — `HookExitCode` 実装と sysexits.h 由来 doc コメント
* `src/main.rs` — `parse_stdin` / `run_hook` / `run_prefetch` / `fail` / `emit_*` 関数群
* `README.md` の Exit Codes / JSON Output Mode セクション
* dotclaude ADR-0065 "scout JSON output schema and sysexits exit code policy" (inspiration; lives in a private dotclaude store, not navigable from this repo)
* dotclaude ADR-0066 "CLI exit code policy grouped by error topology" (inspiration; private dotclaude store) — guardrails is a hook tool consuming stdin JSON and emitting violations on stderr; its exit code map follows the hook-tool grouping defined there.
* Standards: sysexits.h (`man 3 sysexits`)
