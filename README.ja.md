[English](README.md) | **日本語**

# guardrails

Claude CodeのPreToolCall hook用コード品質チェッカー。外部リンターとカスタムルールを組み合わせて、コードを検証し修正提案を提供します。

## 特徴

| 機能                          | 説明                                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------------------- |
| oxlint自動確保                | [oxlint](https://oxc.rs)を自動検出・ダウンロード（手動インストール不要）                                |
| AI向けdenyルール              | `no-explicit-any`、`ban-ts-comment`、`no-non-null-assertion`、`no-console` をデフォルト有効化           |
| カスタムルール                | 外部リンターがカバーしないセキュリティパターン（JS/TS）                                                 |
| ASTベースセキュリティチェック | [oxc](https://oxc.rs)パーサーによる深層解析（コマンドインジェクション、スタック露出、パストラバーサル） |
| Claude最適化出力              | stderrに修正提案を出力                                                                                  |

## インストール

### Claude Code Plugin（推奨）

バイナリのインストールとhookの登録が自動で行われます。

```bash
claude plugins marketplace add thkt/sentinels
claude plugins install guardrails
```

バイナリが未インストールの場合、同梱のインストーラを実行してください。

```bash
~/.claude/plugins/cache/guardrails/guardrails/*/hooks/install.sh
```

### Homebrew

```bash
brew install thkt/tap/guardrails
```

### リリースバイナリから

[Releases](https://github.com/thkt/guardrails/releases)から最新バイナリをダウンロードしてください。

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/guardrails/releases/latest/download/guardrails-aarch64-apple-darwin.tar.gz | tar xz
mv guardrails ~/.local/bin/
```

### ソースから

```bash
cd /tmp
git clone https://github.com/thkt/guardrails.git
cd guardrails
cargo build --release
cp target/release/guardrails ~/.local/bin/
cd .. && rm -rf guardrails
```

## 使い方

### Claude Code Hookとして

プラグインとしてインストールした場合、hookは自動で登録されます。手動で設定する場合は `~/.claude/settings.json` に追加してください。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "guardrails",
            "timeout": 1000,
            "type": "command"
          }
        ],
        "matcher": "Write|Edit|MultiEdit"
      }
    ]
  }
}
```

## 要件

外部リンターの手動インストールは不要です。guardrailsがoxlintを自動で解決します。

1. `node_modules/.bin/oxlint`（プロジェクトローカル）
2. `PATH` 上の `oxlint`（グローバルインストール）
3. `~/.cache/guardrails/bin/oxlint-{version}`（キャッシュ済みダウンロード）
4. GitHub Releasesから自動ダウンロード（初回のみ）

全ステップ失敗時（ネットワーク不通等）はカスタムルールのみで続行します（fail-open）。

| 条件                  | 使用リンター            |
| --------------------- | ----------------------- |
| oxlint が見つかる     | oxlint + カスタムルール |
| oxlint が見つからない | カスタムルールのみ      |

プロジェクト設定ファイル（`oxlintrc.json`）がある場合は自動的に使用されます。

### Prefetch

`guardrails prefetch` は解決チェーンのステップ 3–4 を先取り実行します。oxlint がキャッシュ済み or PATH 上にあればネットワーク通信なしで終了し、なければ GitHub Releases からダウンロードします。

```bash
guardrails prefetch
```

用途:

- インストール時に先取りして、初回 `Write`/`Edit` のダウンロード待ちを回避
- CI でテスト実行前にキャッシュを温める
- エアギャップ環境向けの事前ステージング（接続環境で実行 → `~/.cache/guardrails/bin/` をコピー）

| 結果                                          | Exit |
| --------------------------------------------- | ---- |
| キャッシュ済み or ダウンロード成功            | 0    |
| ダウンロード失敗（ネットワーク or 非対応OS） | 1    |

### AI向けdenyルール

guardrailsはAIコード生成で重要な以下のルールを `--deny` で有効化します（oxlintデフォルトではOFF）。

| ルール                             | 理由                                   |
| ---------------------------------- | -------------------------------------- |
| `typescript/no-explicit-any`       | AIが `any` / `as any` で型を逃がす     |
| `typescript/ban-ts-comment`        | AIが `@ts-ignore` で型エラーを黙殺する |
| `typescript/no-non-null-assertion` | AIが `!` でnullチェックをサボる        |
| `eslint/no-console`                | AIがデバッグ用 `console.log` を残す    |

`oxlint.deny` / `oxlint.allow` でカスタマイズ可能です（設定セクション参照）。

## カスタムルール

外部リンターを補完するカスタムルールは `src/rules/` を参照してください。

### ルール

| ルール             | 重大度   | 説明                                                                            | 無効化する場面                                       |
| ------------------ | -------- | ------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `sensitiveFile`    | Critical | .env、credentials.\*、\*.pem への書き込みをブロック                             | 無効化不可（セキュリティ上重要）                     |
| `cryptoWeak`       | High     | MD5、SHA1、DES、RC4 の使用を検出                                                | 既知の制約があるレガシーシステムの保守               |
| `sensitiveLogging` | High     | console.log 内の password/token/secret を検出                                   | 無効化不可（セキュリティ上重要）                     |
| `security`         | High     | XSS ベクター、安全でない API、postMessage                                       | 無効化不可（セキュリティ上重要）                     |
| `architecture`     | High     | レイヤー違反（例: UI がドメインをインポート）                                   | 小規模プロジェクト、モノリス、スクリプト             |
| `eval`             | High     | eval()、new Function()、間接的 eval                                             | 無効化不可（セキュリティ上重要）                     |
| `hardcodedSecrets` | High     | ソースコード内の API キー、トークン、パスワード                                 | 無効化不可（セキュリティ上重要）                     |
| `openRedirect`     | High     | ユーザー制御入力による location.href/assign                                     | Web 以外のプロジェクト                               |
| `rawHtml`          | High     | 変数を含む HTML の文字列結合                                                    | Web 以外のプロジェクト                               |
| `httpResource`     | Medium   | HTTP（非 HTTPS）リソース URL                                                    | 開発専用の設定                                       |
| `transaction`      | Medium   | トランザクションラッパーなしの複数書き込み                                      | データベースを使用しないプロジェクト                 |
| `domAccess`        | Medium   | React（.tsx/.jsx）での直接 DOM 操作                                             | React 以外のプロジェクト、またはバニラ JS/TS         |
| `syncIo`           | Medium   | readFileSync、writeFileSync（イベントループをブロック）                         | CLI ツール、ビルドスクリプト、同期のみのコンテキスト |
| `bundleSize`       | Medium   | lodash/moment のフルインポート                                                  | バックエンド/Node.js（バンドルサイズの懸念なし）     |
| `testAssertion`    | Medium   | expect() や assert のないテスト                                                 | Playwright、カスタムテストフレームワーク             |
| `flakyTest`        | Low      | テスト内の setTimeout、Math.random                                              | 意図的なタイミング/ランダムネスのテスト              |
| `generatedFile`    | High     | \*.generated.\*、\*.g.ts の編集を警告                                           | コード生成のないプロジェクト                         |
| `testLocation`     | Medium   | src/ ディレクトリ内のテストファイル                                             | コロケーションテスト戦略（ソースと同じ場所）         |
| `naming`           | Mixed    | 命名規則（hooks、コンポーネント、型）                                           | チーム/プロジェクトで異なる命名規則がある場合        |
| `noUseEffect`      | Medium   | .tsx/.jsx内のuseEffectを検出し代替案を提示                                      | useEffectを意図的に使用するプロジェクト              |
| `astSecurity`      | Mixed    | ASTベース: コマンドインジェクション、スタック露出、パストラバーサル（下記参照） | Node.js以外のプロジェクト                            |

### ASTセキュリティルール（`astSecurity`）

[oxc](https://oxc.rs)パーサーによる深層セキュリティチェック。ASTを直接解析し、正規表現ベースのパターンマッチングの偽陰性を回避します。

| サブルール                | 重大度 | 説明                                                              |
| ------------------------- | ------ | ----------------------------------------------------------------- |
| `child-process-injection` | High   | exec/execSync/spawn/spawnSyncへの非リテラル引数                   |
| `err-stack-exposure`      | High   | HTTPレスポンス（res.json/res.send）でのエラースタックトレース漏洩 |
| `non-literal-fs-path`     | Medium | fs.\*呼び出しでの非リテラルファイルパス（パストラバーサルリスク） |

## サブコマンド

```text
guardrails [--json] [COMMAND]

Commands:
  prefetch  Download oxlint binary into the cache (no-op if already present)
  help      Print help for a subcommand

Options:
      --json     Emit violations as a structured JSON report on stdout (hook mode only)
  -h, --help     Print help
  -V, --version  Print version
```

サブコマンドなしで `guardrails` を呼ぶと **hook モード**（stdin から tool_input JSON を読む）になります。`guardrails --help` で終了コードを含む完全な説明を表示できます。

## 終了コード

| コード | 意味                                                                         |
| ------ | ---------------------------------------------------------------------------- |
| 0      | チェック合格、またはサブコマンド成功                                         |
| 1      | I/O エラー / 不正な JSON 入力 / prefetch 失敗                                |
| 2      | ブロッキング違反検出（Claude Code が tool 呼び出しを停止）                   |
| 64     | 使用方法エラー（clap parse 失敗、sysexits.h `EX_USAGE`）                     |

## JSON 出力モード

`--json` フラグを渡すと stdout に構造化された JSON レポートを出力します。人間向けの出力は stderr に残り、終了コードも変わりません。Claude Code などのエージェントが安定したパース可能な契約を必要とするケースを想定しています。

```sh
guardrails --json < tool-call.json
```

> **BREAKING (v0.15+)**: v0.14 で利用できた `GUARDRAILS_JSON=1` env は削除されました。代わりに `--json` を使ってください。すべての hook 呼び出しで JSON を出力したい場合は、hook の `command` にフラグを追加してください ([Claude Code Hookとして](#claude-code-hookとして)参照)。

> **BREAKING (v0.15+)**: 成功時の出力は [ADR-0065](https://github.com/thkt/scout/blob/main/docs/decisions/0065-scout-json-output-schema-and-sysexits-exit-code-policy.md) に従って `SuccessEnvelope` (`{ data, degraded, notes }`) で wrap されます。旧 schema (`{ violations, decision, exit_code }`) は廃止 — hook 判定はプロセス終了コードを参照してください。

### Success envelope

```json
{
  "data": {
    "violations": [
      {
        "rule": "eval",
        "severity": "high",
        "fix": "Avoid eval(). Use JSON.parse() for data or safe alternatives.",
        "file": "/src/app.ts",
        "line": 1
      }
    ],
    "decision": "block"
  },
  "degraded": false,
  "notes": []
}
```

| フィールド        | 型                                              | 補足                                                                  |
| ----------------- | ----------------------------------------------- | --------------------------------------------------------------------- |
| `data.violations` | 配列                                            | ブロッキングと警告の両方を含む。`severity` で区別可能                 |
| `data.decision`   | `"block"` / `"allow"`                           | `severity.blockOn` に一致するエントリが 1 件以上ある場合のみ `block`  |
| `severity`        | `"critical"` / `"high"` / `"medium"` / `"low"`  | 小文字                                                                |
| `line`            | 整数または `null`                               | 位置が不明な場合は `null`                                             |
| `degraded`        | bool                                            | ツール不在 (例: oxlint 未インストール) で `true`                      |
| `notes`           | 文字列の配列                                    | degrade の理由。non-empty なら `degraded: true`                       |

### Error envelope

`--json` 設定時に stdin が不正 (malformed JSON / oversized / IO 失敗) な場合、stdout に `ErrorEnvelope` が出力されます。hook の終了コード (`1` / `2`) は維持されます。

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

| フィールド          | 型                                                                                | 補足                                       |
| ------------------- | --------------------------------------------------------------------------------- | ------------------------------------------ |
| `error.code`        | `"USAGE_ERROR"` / `"DATA_ERROR"` / `"NOT_FOUND"` / `"IO_ERROR"` / `"TEMP_FAILURE"` | ADR-0065 準拠の SCREAMING_SNAKE_CASE       |
| `error.message`     | string                                                                            | 人間向けの詳細 (stderr にも出力される)     |
| `error.next_step`   | string (optional)                                                                 | 復旧のための具体的なアクション             |
| `error.candidates`  | 文字列の配列 (optional)                                                           | 復旧候補 (空なら省略)                      |
| `error.retryable`   | bool                                                                              | 一時的な失敗の場合のみ `true`              |

> **ケース混在**: `severity` は小文字 (v0.14 からの継承) で `error.code` は SCREAMING_SNAKE_CASE (ADR-0065)。意図的な混在で、両 shape は安定しています。

`--json` を付けない場合、出力は人間向けデフォルトモードとバイト単位で完全互換です。

## 設定

プロジェクトルートの `.claude/tools.json` に `guardrails` キーを追加します。すべてのフィールドはオプションで、オーバーライドしたいもののみ指定してください。

> **移行**: プロジェクトルートの `.claude-guardrails.json` もレガシーフォールバックとしてサポートされています。両方存在する場合、`.claude/tools.json` が優先されます。

設定ファイルがない場合のデフォルト構成です。

- すべてのルールが有効
- `critical`と`high`の重大度でブロック

### スキーマ

```json
{
  "guardrails": {
    "enabled": true,
    "rules": {
      "oxlint": true,
      "sensitiveFile": true,
      "cryptoWeak": true,
      "sensitiveLogging": true,
      "security": true,
      "architecture": true,
      "eval": true,
      "hardcodedSecrets": true,
      "openRedirect": true,
      "rawHtml": true,
      "httpResource": true,
      "transaction": true,
      "domAccess": true,
      "syncIo": true,
      "bundleSize": true,
      "testAssertion": true,
      "generatedFile": true,
      "testLocation": true,
      "naming": true,
      "flakyTest": true,
      "noUseEffect": true,
      "astSecurity": true
    },
    "oxlint": {
      "deny": [],
      "allow": []
    },
    "severity": {
      "blockOn": ["critical", "high"]
    }
  }
}
```

#### `oxlint.deny` / `oxlint.allow`

denyリストにルールを追加、またはデフォルトdenyから除外できます。

```json
{
  "guardrails": {
    "oxlint": {
      "deny": ["eslint/curly"],
      "allow": ["eslint/no-console"]
    }
  }
}
```

- `deny`: `--deny` で追加有効化するルール（デフォルトとマージ）
- `allow`: denyリストから除外するルール（例: CLIプロジェクトで `console.log` を許可）

### 設定例

デフォルト構成（設定ファイル不要）。全ルール有効、oxlint自動確保、AI向けdenyルール有効。

カスタムルールのみの構成（oxlint無効）。

```json
{
  "guardrails": {
    "rules": {
      "oxlint": false
    }
  }
}
```

バックエンド（Node.js/API）向け。フロントエンド固有ルール無効化、console許可。

```json
{
  "guardrails": {
    "rules": {
      "domAccess": false,
      "bundleSize": false
    },
    "oxlint": {
      "allow": ["eslint/no-console"]
    }
  }
}
```

すべての重大度でブロックする構成。

```json
{
  "guardrails": {
    "severity": {
      "blockOn": ["critical", "high", "medium", "low"]
    }
  }
}
```

プロジェクト単位でguardrailsを無効化。

```json
{
  "guardrails": {
    "enabled": false
  }
}
```

### 設定の解決

対象ファイルからもっとも近い `.git` ディレクトリまで上方向に探索されます。

```text
project-root/
├── .claude/
│   └── tools.json     ← 優先（guardrails キー）
├── .git/
├── src/
│   └── app.ts         ← チェック対象ファイル → 上方向に設定を探索
└── .claude-guardrails.json  ← レガシーフォールバック
```

## 既存リンターとの併用

lefthook、husky、lint-staged経由でoxlintをコミット時に実行している場合、guardrailsのリンターチェックと重複する可能性がありますが、両者の目的は異なります。

| ツール            | タイミング         | 目的                           |
| ----------------- | ------------------ | ------------------------------ |
| guardrails (hook) | ファイル書き込み時 | 問題が書き込まれる前に防止     |
| lefthook / husky  | コミット時         | コード履歴に入る前の最終ゲート |

oxlintをguardrailsで無効化し、コミットフックに任せる場合の設定です。

```json
{
  "guardrails": {
    "rules": {
      "oxlint": false
    }
  }
}
```

これによりguardrailsのカスタムセキュリティルール（sensitiveFile、cryptoWeak等）を有効に保ちつつ、リンターの重複チェックを回避できます。

## 既知の制限事項

### 行ベースルール（architecture、security、cryptoWeak等）

これらのルールは `non_comment_lines()` を使用し、`/* ... */` ブロックコメントの状態を行間で追跡しつつ `//` 行コメントをフィルタリングします。

- **`/*`や`*/`を含む文字列リテラル** — リテラル内のコメントマーカー（例: `let s = "/* not a comment */";`）を実際のコメント境界として扱い、誤ったフィルタリングを引き起こす可能性がある
- **行頭のアスタリスク** — `*`で始まる行はJSDocの継続行として扱われる

### スキャナーベースルール（sensitiveLogging、testAssertion）

これらのルールは行間でコメント状態を追跡する `StringScanner` を使用します。

- **JavaScript正規表現リテラル** — `//`や`/*`を含むパターン（例: `/https:\/\//`）がコメント開始として誤認識される可能性がある

これらのトレードオフは、偽陰性よりも偽陽性が望ましいguardrailsのユースケースにおいて許容範囲です。

## 関連ツール

| ツール                                         | Hook        | タイミング              | 役割                          |
| ---------------------------------------------- | ----------- | ----------------------- | ----------------------------- |
| **guardrails**                                 | PreToolUse  | Write/Edit 前           | リント + セキュリティチェック |
| [formatter](https://github.com/thkt/formatter) | PostToolUse | Write/Edit 後           | 自動コード整形                |
| [reviews](https://github.com/thkt/reviews)     | PreToolUse  | レビュー系 Skill 実行時 | 静的解析コンテキスト提供      |
| [gates](https://github.com/thkt/gates)         | Stop        | エージェント完了時      | 品質ゲート (knip/tsgo/madge)  |

## ライセンス

MIT
