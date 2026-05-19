---
status: "accepted"
date: 2026-05-19
decision-makers: thkt
---

# Hook 起動時に `.claude/tools.json` を自動生成しない (hint stderr 出力のみ)

## Context and Problem Statement

`src/main.rs` の `show_config_hint` は、`.claude/tools.json` が存在せず親の `.claude/` ディレクトリは存在するときに `{"guardrails": {}}` の payload を持つファイルを自動生成していた。実装は `fs::OpenOptions::new().write(true).create_new(true).open(path)` + `write_all` の 2 段階で、`create_new` 成功後 `write_all` 完了前に SIGKILL を受けると zero-byte ファイルが残る。残ったファイルは以後の hook 起動で invalid config error を返し続ける。

しかし atomicity の修正 (`NamedTempFile::persist` 等) を入れるかどうかの前に、より根本的な論点がある: **validation 目的の PreToolUse hook が、起動するたびにユーザーのプロジェクトに永続ファイルを書き込む副作用を持つこと自体が、OUTCOME.md の Non-goals「非 hook サブコマンド」「事後通知 / ログ出力のみ / 警告止まりで AI 修正サイクルに乗らない設計」の境界と衝突する。**

副作用の存在は次の問題を生む。

1. **責務逸脱**: PreToolUse hook の役割は「AI の編集ごとに stdin JSON 1 ファイル content を audit して blocking signal を返す」こと。永続ファイル生成は project bootstrap の責務であり hook の責務ではない。
2. **atomicity リスクの保守コスト**: hook で write し続ける限り、SIGKILL / disk full / permission error の各シナリオに対する atomic write の保守が永遠についてまわる。
3. **bootstrap タイミングの不透明**: ユーザーは「いつ tools.json が作られたか」を意識できない。hook が静かに生成するため、設定をカスタマイズしたいときに「既に作られていた」状態になっている。
4. **テスト負債**: hook 自体の test と bootstrap 副作用の test が混じり、test fixture が `.claude/` の有無や tools.json 既存状態に分岐する。

`/assert` audit の F-017 (atomic write 不足) と CD-004 (副作用設計) は同じ根を持つ。F-017 を atomic 化で解決すると CD-004 が残るが、CD-004 を「副作用を消す」で解決すれば F-017 は moot になる。

## Decision Drivers

- OUTCOME.md Non-goals との整合: 「非 hook サブコマンド」「事後通知 / ログ出力のみ」と PreToolUse hook の責務境界を一致させる
- F-017 (zero-byte ファイル残留) の根本解消: write 自体を止めれば atomic write の保守コストがゼロになる
- 設定の bootstrap 経路をユーザーが意識できる形にする: 自動生成より hint 経由でユーザーに作成を委ねる方が、設定の起点がドキュメントに集約する
- hook 起動の純度を上げる: stdin JSON 1 ファイル content の audit に集中させ、project-write 副作用を持たない設計に揃える
- guardrails が `.claude/tools.json` の中身 (`{"guardrails": {}}`) を強制する根拠が薄い: 他の AI tool (claude.ai の reviews 等) と共存する file を guardrails 単独の都合で書きに行く構造は越権

## Considered Options

- **A. hook は hint stderr 出力のみ、ファイル生成しない (採用)**: hook 経路から書き込み副作用を完全に削除し、ユーザーは hint を見て手動で `.claude/tools.json` を作る
- B. atomic write で残す: `NamedTempFile::persist` 経由で zero-byte 残留だけ解消、副作用は残す
- C. marker file で 2 回目以降スキップ: `.claude/.guardrails-hinted` のような marker を置いて auto-create attempt を最初の 1 回に限定
- D. 非 hook サブコマンド (`guardrails init` 等) に bootstrap を移す: hook は audit 専任、init は別 entry point

## Decision Outcome

採用: **Option A**。hook から auto-create を削除し、hint stderr 出力のみに揃える。

理由:

- Non-goals「非 hook サブコマンド」と整合: D 案 (`guardrails init` のような subcommand) は memory `Hook Tool Scope Creep` の同種ケース (issue #7 の `guardrails scan`) を YAGNI で close した前例と整合する。caller 実需が出るまで非 hook subcommand は追加しない
- B 案 (atomic 化のみ) は副作用の本質を温存。長期に渡って atomic 保守コストを払い続ける
- C 案 (marker) も「副作用は副作用」の問題を逃すだけで本質を解決しない。marker 自体が hook 起動時の project-write になる
- A 案は破壊的だが影響範囲が限定的: 既存ユーザーの `.claude/tools.json` は触らず、未生成プロジェクトでも hint で誘導できる

### Scope

本 ADR は次を固定する。

- `show_config_hint` は config が default の場合に hint message を stderr に出力する役割のみを持つ。永続ファイルを生成しない
- `.claude/tools.json` の作成はユーザー手動 (README の Configuration セクション参照)
- hook 起動中、guardrails が project directory (`.claude/`, project_root) に対して書き込みを行う副作用は **存在しない** ことを保証する
- `DEFAULT_TOOLS_JSON` const は不要となり削除する

### Out of Scope

- 既存の `.claude/tools.json` の migration (互換性は維持、変更しない)
- `guardrails init` のような bootstrap subcommand の追加 (caller 実需が出るまで)
- hint message 文言の変更 (現行「Guardrails: using defaults. Customize via .claude/tools.json — see ...」を維持)

## Consequences

### Positive

- hook 起動時の project-write 副作用が消え、validation hook 単機能としての純度が上がる
- F-017 (zero-byte 残留) は自動解消、atomic write 保守ゼロ
- test fixture の `.claude/` 状態分岐が `HintAction::Skip | Hint` の 2 値に縮退、cyclomatic complexity 低下
- OUTCOME.md Non-goals との整合性が code 上で表現される

### Negative

- 初回ユーザーは hint を見て手動で `.claude/tools.json` を作る手間が発生する (ただし hint message に URL が含まれ documentation 経路に誘導できる)
- 既に auto-create 経路に依存している外部ドキュメント / blog があった場合、それらが古くなる (現時点で確認できる範囲では guardrails README が唯一の起点)

### Reversibility

低コストで reversible: 再導入する場合は `try_create_tools_json` 相当の関数を atomic write (NamedTempFile::persist) で復活、もしくは `guardrails init` subcommand として実装すれば良い。本 ADR を supersede する形で記録する。
