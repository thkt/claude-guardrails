---
status: "accepted"
date: 2026-05-14
decision-makers: thkt
---

# Post-edit content resolution と degradation contract

## Context and Problem Statement

guardrails は PreToolUse hook として、AI agent の `Write`/`Edit`/`MultiEdit` を編集前に検査する。`Write` の `tool_input.content` は新しい全文を保持しているが、`Edit`/`MultiEdit` の `tool_input` は snippet (`old_string`/`new_string` のペア) のみで、ファイル全体は含まれない。

snippet 単独に対して security check を走らせると、context が不足して false negative が出る (例: `useEffect` 使用判定は import 状況と組み合わせて初めて意味を持つ、SSRF 防御は URL の組み立て全体を見ないと検出できない)。Issue #59 で「JSX snippet alone fails」が報告された後、`Edit`/`MultiEdit` でも disk からファイルを読み、`old_string` を `new_string` に置換して **post-edit 全文** を再構成する設計に切り替えた。

この再構成は常に成功するわけではない。ファイルが既に削除されていた/10MB を超えていた/バイナリだった/`old_string` が disk 上の内容と drift していた/MultiEdit 途中段でパターン不一致になった、等の経路がある。失敗時の挙動 (silent fallback で snippet を渡すか、エラーにするか、警告するか) が曖昧だと、AI agent は「なぜ security check が違う結果を返したか」を解釈できない。

`ContentResolution` 3 値と `DegradedReason` 8 variant の意味論を ADR として固定し、各経路が contract のどの slot に落ちるかを明示する必要がある。

## Decision Drivers

- AI agent の Edit/MultiEdit に対して post-edit 全文で security 判定する (snippet 単独より context-aware)
- 全文取得失敗時、silent fallback ではなく degradation を AI agent に通知する
- 全文不要なケース (`Write` の content そのまま使う/`.md` ファイル/`old_string` 未指定) を degradation と区別する
- 失敗カテゴリを 8 種類に enumerate し、note 文言で AI agent が次の行動を選べるようにする
- 検査自体は止めない (snippet で fallback 後に rule 評価続行)

## Considered Options

- 3 値 `ContentResolution::{Full, Degraded(DegradedReason), NotApplicable}` (採用)
- `Option<String>` (`None` で snippet fallback) + 別 channel で degradation note を返す
- 2 値 `Result<String, DegradedReason>` (`NotApplicable` も `Degraded` 扱いにする)
- snippet を一切渡さず post-edit 全文取得失敗時は exit 70 (fail-closed)

## Decision Outcome

採用: `ContentResolution` 3 値 (`Full`/`Degraded(DegradedReason)`/`NotApplicable`) と `DegradedReason` 8 variant の組合せ。`src/content.rs` で定義。

### ContentResolution 3 値の意味論

| Variant                    | 意味                               | content として渡るもの                                 | degraded note                |
| -------------------------- | ---------------------------------- | ------------------------------------------------------ | ---------------------------- |
| `Full(String)`             | post-edit 全文の再構成成功         | 再構成された全文                                       | 出さない                     |
| `Degraded(DegradedReason)` | 全文取得を試みたが失敗             | snippet (`new_string` / `edits[*].new_string` の join) | 出す (reason に応じた文字列) |
| `NotApplicable`            | 全文取得を試みる前に「不要」と判定 | snippet                                                | 出さない                     |

`NotApplicable` と `Degraded` の境界が重要。

`NotApplicable` は「全文取得しないのが正しい」状態:

- `Write` tool: `tool_input.content` が既に新しい全文 (再構成不要)
- `.md` 等 JS/TS 外: `RE_JS_FILE` 不一致で security check 対象外
- `Edit` の `old_string` 未指定/`MultiEdit` の edit エントリで `old_string` または `new_string` 欠落: 再構成ロジックが動作しない

`Degraded` は「全文取得を試みたが失敗した」状態。AI agent には「次に何が起きると content の取り直しが必要か」を note で伝える。

### DegradedReason 8 variant

`src/content.rs` の `DegradedReason::note` が AI agent 向けの文字列を生成する。

| Variant                      | 発生条件                                                                  | note 文言                                                                                                |
| ---------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `OversizedFile`              | ファイルが `MAX_INPUT_SIZE` (10MB) を超過                                 | "Target file exceeds 10000000-byte limit; analyzed Edit snippet only."                                   |
| `NonUtf8Content`             | バイナリ / 不正 UTF-8                                                     | "Target file is not valid UTF-8; analyzed Edit snippet only."                                            |
| `FileNotFound`               | disk 上にファイルが無い (削除済 / 移動済 / typo)                          | "Target file not on disk; analyzed Edit snippet only."                                                   |
| `PermissionDenied`           | ファイルは存在するが open 不可                                            | "Permission denied reading target file; analyzed Edit snippet only."                                     |
| `IoError`                    | その他の I/O 失敗                                                         | "I/O error reading target file; analyzed Edit snippet only."                                             |
| `OldStringNotFound`          | `Edit` で `old_string` が disk 上の内容と一致しない (drift)               | "Edit pattern not found in target file; analyzed Edit snippet only."                                     |
| `MultiEditMidFailure(usize)` | `MultiEdit` の n 番目で `old_string` が中間状態と一致しない               | "MultiEdit edit {n} did not match post-edit content; analyzed Edit snippet only."                        |
| `PathOutsideProject`         | canonicalize 後のパスが `project_root` 外 (symlink 攻撃 / `..` traversal) | "Target file resolves outside the project root (symlink or path traversal); analyzed Edit snippet only." |

8 variant に分けたのは、AI agent が note を読んで対応行動を選べるようにするため:

- `FileNotFound`/`OldStringNotFound`/`MultiEditMidFailure` → AI 自身の前提 (ファイル状態) と disk が drift しているので Read で確認
- `OversizedFile` → 編集対象ファイルが分割不能なほど大きい可能性 (refactor の signal)
- `NonUtf8Content`/`PermissionDenied`/`IoError` → 環境側の問題
- `PathOutsideProject` → security 上の警告 (symlink 攻撃の可能性)

### Degradation contract

`Degraded(reason)` の場合の挙動 (`run_hook` in `src/hook.rs`):

1. `reason.note()` で文字列を生成
2. stderr に `"guardrails: degraded: {note}"` を出力
3. `notes: Vec<String>` に push
4. `--json` 時は `SuccessEnvelope.notes` に載せる (`degraded: true` になる)
5. snippet を content として security check 続行

security check は止めない。snippet 単独でも false positive が出る方向で動作する (false negative より false positive を優先する `README.md` 既定方針)。

### Notes aggregation order

`run_hook_with_input` (`src/hook.rs`) は単一の `notes: Vec<String>` に複数 source から push してから `SuccessEnvelope` に渡す。順序と作法は固定。

| Order | Source                                                   | Pushed by                       |
| ----- | -------------------------------------------------------- | ------------------------------- |
| 1     | project root canonicalize 失敗 (環境失敗軸)              | `resolve_project_root_or_note`  |
| 2     | config load 失敗 (legacy migration 含む環境失敗軸)       | `load_config_or_note`           |
| 3     | linter (oxlint) 不在 / 起動失敗 (環境失敗軸)             | `lint_with_external_tools`      |
| 4     | `DegradedReason::note()` (post-edit content degradation) | `get_file_and_content` の戻り値 |

固定方針:

- **No dedup**: 同じ理由が複数経路から発生しても両方残す。AI agent は「signal がいくつあるか」も解釈に使う
- **Dual emit**: stderr (human readable) と `SuccessEnvelope.notes` (machine readable) の両方に同じ文字列が出る
- **Early-return も propagate**: unsupported tool/empty content で content 解析自体をスキップする経路でも、Order 1 (project root) は既に push 済みのため `notes` を envelope に流す。`degraded` flag が environmental degradation を反映するためで、`get_file_and_content` が `None` を返した側で notes を捨ててはならない

### Degraded derivation semantics

`SuccessEnvelope.degraded` は `src/io/envelope.rs::SuccessEnvelope::with_notes_and_info` で degradation notes の有無 (`!degradations.is_empty()`) として派生する。次の意味を持つ。

- `degraded: true` は `ContentResolution::Degraded` 由来に限らず、上記 Order 1〜4 のどれか 1 つでも degradation note が積まれた状態を包含する
- 「ContentResolution::Degraded」と「any environmental note present」を **同じ flag に union** している。flag 単体では原因軸を区別できない設計
- AI agent は `degraded: true` を見ても失敗事由を判断せず、必ず `notes` を読んで対応行動を選ぶ契約。flag は「`notes` を読むべき signal」のみを意味する
- degradation notes が空であれば `degraded: false`、1 件以上なら `degraded: true` (`SuccessEnvelope::with_notes_and_info` の不変条件)
- diff-aware の降格件数報告 ([ADR-0020](0020-diff-aware-demotion-of-preexisting-violations.md)) は wire 上の `notes` の末尾に連結されるが degradation ではないため flag を立てない。`notes` non-empty かつ `degraded: false` は件数報告のみの状態を意味する
- 経路の境界は固定。envelope 側で flag derivation logic を変えると Order 1〜4 のいずれの caller も影響を受ける

### Consequences

- Good, AI agent は note を読んで「次にどの行動を取れば content 取り直せるか」を判断できる
- Good, `NotApplicable` を `Degraded` から分離することで、`Write` や `.md` で note が出ない (誤った degradation signal を流さない)
- Good, 8 variant が `DegradedReason::note` 1 箇所に集約され、文言改善が単一箇所で済む
- Good, security check が止まらないため、AI agent の編集サイクルが詰まらない (snippet 単独でも検出機会を残す)
- Bad, `OldStringNotFound` と `MultiEditMidFailure` は AI agent 側の前提 drift も含むので、note を読まずに無視すると同じ violation が次の hook でも報告される
- Bad, 8 variant の網羅性は audit で確認した範囲のみ。将来 I/O 経路が増えると (例: 非同期 watch、remote fs) variant 不足が出る可能性

### Confirmation

`ContentResolution` 3 値と `DegradedReason` 8 variant は次のテストで pin されている (`src/content/tests.rs`)。

| 確認内容                                                         | テスト                                                                                                                                     |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `Full` 経路 (post-edit 全文再構成成功)                           | `read_file_capped_returns_full_for_valid_js` / `edit_reads_full_file_and_applies_substitution` / `multi_edit_applies_sequentially_to_file` |
| `NotApplicable` 経路 (`.md` skip)                                | `read_file_capped_returns_not_applicable_for_non_js` / `resolve_edit_content_not_applicable_without_old_string`                            |
| `Degraded(FileNotFound)`                                         | `read_file_capped_degrades_on_file_not_found` / `edit_falls_back_to_snippet_when_file_missing` / `multi_edit_falls_back_when_file_missing` |
| `Degraded(NonUtf8Content)`                                       | `read_file_capped_degrades_on_non_utf8`                                                                                                    |
| `Degraded(OversizedFile)`                                        | `read_file_capped_degrades_on_oversized_file` / `read_file_capped_accepts_exactly_max_size` (境界)                                         |
| `Degraded(OldStringNotFound)`                                    | `resolve_edit_content_degrades_on_old_string_not_found` / `edit_falls_back_to_snippet_when_old_string_not_found`                           |
| `Degraded(MultiEditMidFailure(idx))`                             | `resolve_multi_edit_content_degrades_on_mid_failure` (idx が正しい index で返ること)                                                       |
| `Degraded(PathOutsideProject)`                                   | `read_file_capped_degrades_when_file_outside_explicit_root` / `read_file_capped_degrades_on_symlink_pointing_outside_root` (unix)          |
| `get_file_and_content` の `DegradedReason` 伝播                  | `get_file_and_content_propagates_degraded_reason`                                                                                          |
| note 文言                                                        | `degraded_reason_note_contains_actionable_text`                                                                                            |
| RC-001 (full-file fail → snippet fallback + `degraded: true`)    | `tests/cli/edit.rs:56-83` (`edit_snippet_fallback_emits_degraded_true_in_json_envelope`)                                                   |
| TC-004 (エラー優先順位 PathOutsideProject > MultiEditMidFailure) | `tests/cli/edit.rs:85-116` (`multi_edit_mid_sequence_failure_propagates_to_envelope`)                                                      |
| issue #59 (JSX snippet alone fails → full-file resolution)       | `tests/cli/edit.rs:22-54` (`edit_with_jsx_attribute_snippet_detects_via_full_file`)                                                        |

新規 `DegradedReason` variant を追加する PR では、note 文言と上記 confirmation 表への追加を必須にする。

## Pros and Cons of the Options

### 3 値 `Full` / `Degraded(reason)` / `NotApplicable` (採用)

- Good, `Degraded` と `NotApplicable` を分離し、note が出る条件を明確にできる
- Good, `DegradedReason` を enum で 8 variant に固定、note 文言を集約
- Bad, 3 値 + 8 variant の組合せで API 表面が大きい (新規読者の学習コスト)

### `Option<String>` + 別 channel で note

- Good, シグネチャがシンプル
- Bad, `None` の意味が場所によって `NotApplicable` と `Degraded` 両方混在し、新規読者が判別できない
- Bad, note を別 channel で渡すと call site で渡し忘れが起きる

### 2 値 `Result<String, DegradedReason>` (`NotApplicable` も Degraded 扱い)

- Good, シグネチャがシンプル
- Bad, `Write` や `.md` で degraded note が出ることになり、AI agent が誤った degradation signal を受け取る
- Bad, `NotApplicable` は意図的な skip で、retry や対応行動を促す note は不適

### 全文取得失敗時に exit 70 (fail-closed)

- Good, security 最大化、snippet 単独 false negative の可能性ゼロ
- Bad, ファイル削除直後の Edit 等で AI 作業が完全停止 (UX 悪化、ADR-0004 環境失敗軸と齟齬)
- Bad, false positive が増える方向ではなく hook が動かなくなる方向で fail する

## More Information

### Quality Attributes

| Attribute                | Priority | Approach                                          |
| ------------------------ | -------- | ------------------------------------------------- |
| 検出精度 (context-aware) | High     | post-edit 全文で security check                   |
| AI agent への signal 質  | High     | 8 variant で degraded note を生成、行動を促す文言 |
| 検出継続性               | High     | 全文失敗でも snippet で check 続行                |
| 拡張性                   | Medium   | enum に variant 追加、`note()` で文字列追加       |

### Trade-offs

| 失う                                               | 得る                                       |
| -------------------------------------------------- | ------------------------------------------ |
| `Degraded` 時 snippet で false positive 増の可能性 | 検査を止めず編集サイクル維持               |
| 3 値 + 8 variant の学習コスト                      | `NotApplicable` と `Degraded` の意図的分離 |
| 8 variant 網羅性は audit 時点                      | 各 variant に対応する具体的 note 文言      |

### Reassessment Triggers

- 既存 variant では分類できない degradation が発見された場合 (例: 非同期 watch/remote fs/encrypted file)、新 variant + note 文言追加
- `OldStringNotFound`/`MultiEditMidFailure` が異常頻度で発生する事象が観測された場合、AI agent 側に「事前に Read してから Edit」を促す note 文言改善
- `PathOutsideProject` が実際の symlink 攻撃で再現された場合、`Degraded` ではなく `exit 64` (fail-closed) への昇格を検討
- snippet 単独 false positive の苦情が来た場合、本 ADR の "検出継続性" 方針を見直し

### References

- `src/content.rs` (`ContentResolution`, `DegradedReason`, `DegradedReason::note`, `get_file_and_content`, `resolve_edit_content`, `resolve_multi_edit_content`, `read_file_capped`, `apply_edit`, `io_error_to_reason`)
- `tests/cli/edit.rs` (RC-001/TC-004/issue #59 シナリオ)
- ADR-0004 (Fail-mode policy) — `Degraded` は環境失敗軸に該当
- `README.md` の "Known Limitations"/"JSON Output Mode" (degraded notes 例示)

## Amendment 2026-06-24: invariant gate の `.json` full content は共有 resolution を read-gate 強制 open で再利用

2026-06-24 census で新規 ADR 昇格を見送った判断 (I6) を記録する。#359 の invariant gate が本 ADR の content resolution contract をどう再利用するかの cross-module seam を確定する。

invariant gate は post-edit の full content を必要とする (pin した scalar と突き合わせるため)。新しい resolution logic を起こさず、`content.rs` の `reconstruct_structured_full` が本 ADR の `resolve_edit_content`/`resolve_multi_edit_content` をそのまま再利用する。通常 `is_js` が担う read gate を強制 open にして呼ぶことで、`is_js=false` の `.json` Edit も snippet でなく full に再構築される。

| 性質                       | 挙動                                                                                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| gate predicate             | `reconstruct_structured_full` は `is_structured_config` を gate にする。非 `.json` は disk read 前に `NotApplicable` を返す              |
| 共有する resolution        | 既存の Edit / MultiEdit resolution を read gate 強制 open で呼ぶ。実効 read gate は `is_js` または `is_structured_config`                |
| 既存 content-scan への影響 | target の snippet `content` は触らない。full は別値 `structured_full` として返り、既存 content-scan rule (JS 向け regex 群) には渡さない |
| 非対象 file のコスト       | 非 `.json` かつ非 JS の Edit (`.css` / `.md` 等) はどちらの predicate も false で再構築せず、NFR-001 のとおりコスト 0                    |

新 logic を起こさず既存 resolution に相乗りさせたのは、本 ADR の `ContentResolution`/`DegradedReason` 契約をそのまま継承するため。reconstruction 失敗時は本 ADR の `Degraded(reason)` 経路に乗り、`NotApplicable` に潰さない。invariant pass は full content を受け取れず skip し、`degraded_note` が human に手動再検証を促す。NFR-001 の「非対象 file はコスト 0」は `run_invariant_pass` 側で `structured_full` が None なら disk read 前に短絡することで担保する。

### Related (I6)

- `src/content.rs` (`reconstruct_structured_full`, `resolve_edit_content`/`resolve_multi_edit_content` の read-gate 強制 open)
- `src/invariant.rs` (`is_structured_config`, `run_invariant_pass` の NFR-001 短絡)
- ADR-0016 Amendment (invariant gate の `.json` scope)
- ADR-0023 (stateless path-consistent invariant gate)

## Amendment 2026-08-15: 空 content は degradation ではない、`get_file_and_content` の早期 return を取得失敗のみに絞る

issue #454 で報告された false negative を記録する。`get_file_and_content` の早期 return は `file_path.is_empty() || content.is_empty()` だった。空の `new_string`/`content` は削除編集として正当な値だが、この条件では取得失敗と同じ扱いで `None` を返し、`ResolvedTarget` 自体が組まれず `collect_violations` の評価対象から外れていた。`.guardrails.json` の 1 行を空 `new_string` の `Edit` で削る操作は、`config_guard` (path のみで判定し `content` を読まない rule) が発火すべき対象でありながら、この早期 return で `collect_violations` に到達すらしなかった。

採用: 早期 return の条件を `content.is_empty() && structured_full.as_full_str().is_none()` に絞る (`src/content.rs`)。空 content 単独では skip しない。

### 空 content と取得失敗の区別

「空 content」と「取得失敗」は別の状態として扱う。

| 状態                                                          | 判定                                                                | `get_file_and_content` の挙動                                             |
| ------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| 空 content (削除編集)                                         | snippet (`content` / `new_string`) が空                             | skip しない。`structured_full` が `Full` を持てば `ResolvedTarget` を返す |
| 取得失敗 (`file_path` 欠落)                                   | `file_path` が空                                                    | 常に `None` (変更前と同じ)                                                |
| 取得失敗 (snippet も `structured_full` も content を持たない) | `content.is_empty()` かつ `structured_full.as_full_str()` が `None` | `None`                                                                    |

空 content 単独を degradation 扱いにしないのは、本 ADR の `NotApplicable` と `Degraded` の境界と同じ理由による。`new_string` が空の `Edit` は「全文取得を試みたが失敗した」のではなく、ファイルの一部を消す意図どおりの編集で、`ContentResolution::Degraded` のどの `DegradedReason` にも当たらない。この変更は `ContentResolution` に新しい variant を足さず、`get_file_and_content` が `ResolvedTarget` を組むかどうかの gate だけを変える。`.json` 以外で `structured_full` が `NotApplicable` のままの場合、空 content かつ全文も無い状態は変更前と同じく `None` になる (`.ts` ファイルの空 `new_string` 削除など)。

### Related (U-001/U-002)

- `src/content.rs` (`get_file_and_content` の早期 return 条件)
- `src/content/tests.rs` T-530 (`.json` の空 `new_string` 削除で `structured_full` から全文が返る), T-531 (`file_path` 空は従来どおり取得失敗), T-532 (`structured_full` が組めない種類のファイルで空 content は従来どおり skip)
- `src/hook/tests.rs` T-533 (`.guardrails.json` の空 `new_string` 削除で `config_guard` が発火), T-534 (pin 済み `.json` の空 `new_string` 削除で invariant gate に届く)
- issue #454
