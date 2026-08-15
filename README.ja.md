[English](README.md) | **日本語**

# guardrails

Claude Code の PreToolUse hook 用コード品質チェッカー。外部リンターとカスタムルールを組み合わせて、コードを検証し修正提案を提供します。

## 特徴

| 機能                          | 説明                                                                                                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| oxlint自動確保                | [oxlint](https://oxc.rs)を自動検出・ダウンロード（手動インストール不要）                                                                  |
| AI向けdenyルール              | `no-explicit-any`、`ban-ts-comment`、`no-non-null-assertion`、`no-console`、`no-new-func`、`rules-of-hooks`、`jsx-key` をデフォルト有効化 |
| カスタムルール                | 外部リンターがカバーしないセキュリティパターン（JS/TS）                                                                                   |
| ASTベースセキュリティチェック | [oxc](https://oxc.rs)パーサーによる深層解析（コマンドインジェクション、スタック露出、パストラバーサル）                                   |
| Claude最適化出力              | stderrに修正提案を出力                                                                                                                    |

## インストール

### Claude Code Plugin（推奨）

バイナリのインストールと hook の登録が自動で行われます。

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

プラグインとしてインストールした場合、hook は自動で登録されます。手動で設定する場合は `~/.claude/settings.json` に追加してください。

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

外部リンターの手動インストールは不要です。guardrails が oxlint を自動で解決します。

1. `node_modules/.bin/oxlint`（プロジェクトローカル）
2. `PATH` 上の `oxlint`（グローバルインストール）
3. `~/.cache/guardrails/bin/oxlint-{version}`（キャッシュ済みダウンロード）
4. GitHub Releases から自動ダウンロード（初回のみ）

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

| 結果                                                            | Exit | `error.code` |
| --------------------------------------------------------------- | ---- | ------------ |
| キャッシュ済み or ダウンロード成功                              | 0    | (なし)       |
| 非対応プラットフォーム (Windows / 非 amd64 等)                  | 65   | `DATA_ERROR` |
| ネットワーク失敗 (ダウンロード / read エラー)                   | 74   | `IO_ERROR`   |
| 展開失敗 (tar / cache 書き込み / rename)                        | 74   | `IO_ERROR`   |
| キャッシュディレクトリ未利用可 (`XDG_CACHE_HOME` / `HOME` 不在) | 74   | `IO_ERROR`   |

> **BREAKING (v0.15+)**: `prefetch` の終了コードが `0` / `1` から sysexits.h 値 (`0` / `65` / `74`) に変更されました。`--json` を渡すと失敗時に構造化 `ErrorEnvelope` (`{ error: { code, message, next_step, retryable } }`) が返されます。

### AI向けdenyルール

guardrails は AI コード生成で重要な以下のルールを `--deny` で有効化します（oxlint デフォルトでは OFF）。

| ルール                             | 理由                                                            |
| ---------------------------------- | --------------------------------------------------------------- |
| `typescript/no-explicit-any`       | AIが `any` / `as any` で型を逃がす                              |
| `typescript/ban-ts-comment`        | AIが `@ts-ignore` で型エラーを黙殺する                          |
| `typescript/no-non-null-assertion` | AIが `!` でnullチェックをサボる                                 |
| `eslint/no-console`                | AIがデバッグ用 `console.log` を残す                             |
| `eslint/no-new-func`               | AIが `new Function(...)` で動的にコード生成する                 |
| `react/rules-of-hooks`             | AIがhookを呼ぶ関数に `use` 接頭辞を付けない                     |
| `react/jsx-key`                    | AIが `key` 無しの `map` を書き、list item の state が入れ替わる |

> **注:** `new Function(...)` は oxlint の `eslint/no-new-func`（`--deny` 経由で High）とカスタム `eval` ルール（High）の両方で検出されます。これにより oxlint の diagnostic の後にも guardrails 固有の fix メッセージがエージェントに届きます。stderr の順は oxlint が先。

`react/rules-of-hooks` と `react/jsx-key` は oxlint の react plugin を要求しますが、この plugin はデフォルト OFF です。guardrails は、編集対象を含む package の `package.json` が `dependencies`/`devDependencies`/`peerDependencies` のいずれかで react を宣言しているときだけ有効化します。判定は編集対象から 10 階層まで遡った最寄りの `package.json` ただ 1 個で行います。Vue や Nuxt の composable は `.ts` に住むため、この gate が無いと React Hook として報告されます。plugin は react の他 16 ルールを道連れに有効化しますが、oxlint はそれらを warning で返すため、デフォルトの `blockThreshold` では編集を止めません。[ADR-0032](docs/decisions/0032-enable-the-oxlint-react-plugin-for-hook-naming.md)参照。

`react/jsx-key` は plugin が既に有効化しているルールで、oxlint は warning で返します。`--deny` は編集を止めるために severity を error へ上げるためだけに出しています。plugin が OFF のプロジェクトでは、この `--deny` は何にも一致しません。

無効化するには `oxlint.allow` にそのルール名を書きます。これは config に書くキーで、stderr に出る id は `oxlint/eslint-plugin-react-hooks(rules-of-hooks)` と `oxlint/eslint-plugin-react(jsx-key)` という別の文字列です。

`oxlint.deny`/`oxlint.allow` でカスタマイズ可能です（設定セクション参照）。

## カスタムルール

外部リンターを補完するカスタムルールは `src/rules/` を参照してください。

### ルール

<!-- BEGIN GENERATED: rules-table -->
| ルール | 重大度 | 説明 | なぜ重要か | 無効化する場面 |
| --- | --- | --- | --- | --- |
| `sensitiveFile` | Critical | .env、credentials.\*、\*.pem への書き込みをブロック | 一度コミットすると git 履歴と CI ログに永続化し、無効化にはローテートが必要になる | 無効化不可（セキュリティ上重要） |
| `cryptoWeak` | High | MD5、SHA1、DES、RC4 の使用を検出 | 衝突攻撃や鍵回復が現実的で、プリミティブ自体が約束した保証を提供できない | 既知の制約があるレガシーシステムの保守 |
| `sensitiveLogging` | High | console.log 内の password/token/secret を検出 | ログは CI runner / 監視 sink / クラッシュレポータに流れ、下流の全ての読み手にシークレットが届く | 無効化不可（セキュリティ上重要） |
| `security` | Mixed | XSS ベクター、安全でない API、機密ストレージ。rule_id 別の内訳は下記の `Security Rules` を参照 | 各パターンが eval sink もしくは origin から読み取れる storage で、同一オリジンの任意スクリプトが state を抜ける | 無効化不可（セキュリティ上重要） |
| `architecture` | High | レイヤー違反（例: UI がドメインをインポート） | UI がドメイン内部に到達すると境界が将来の変更を制約しなくなり、refactor が止まる | 小規模プロジェクト、モノリス、スクリプト |
| `eval` | High | eval()、new Function()、間接的 eval | そこに到達した文字列はそのままコードとして走るので、汚染入力が任意コード実行に化ける | 無効化不可（セキュリティ上重要） |
| `hardcodedSecrets` | High | ソースコード内の API キー、トークン、パスワード | リポジトリを push した瞬間にキーは公開され、ローテート以外に対処手段が無い | 無効化不可（セキュリティ上重要） |
| `cotLeakageMarker` | High | AI Chain-of-Thought リークマーカー (`<thinking>`、`<\|channel\|>`、`<\|start\|>assistant`、`to=functions.`) | コピペで生き残ったタグごと、モデル内部状態が本番ログ / UI / ドキュメントに流出する | AI トレース/トランスクリプトを意図的に保存するプロジェクト |
| `openRedirect` | High | ユーザー制御入力による location.href/assign | 攻撃者が遷移先を選べるのに URL は自オリジンを纏ったままで、フィッシングの理想形になる | Web 以外のプロジェクト |
| `rawHtml` | High | 変数を含む HTML の文字列結合 | 文字列結合 HTML は攻撃者入力をそのまま live DOM に置く XSS sink | Web 以外のプロジェクト |
| `sqliConcat` | High | テンプレートリテラル/文字列結合で組み立てた SQL を検出 | 補間 SQL はユーザー入力をクエリ本体に混入させる、典型的な SQL injection | データベースを使用しないプロジェクト |
| `httpResource` | Medium | HTTP（非 HTTPS）リソース URL | 非 TLS リソースは on-path 攻撃者が中身を差し替えられる（mixed-content downgrade、サプライチェーン改竄） | 開発専用の設定 |
| `corsWildcard` | Medium | CORS ワイルドカード origin (`cors({ origin: '*' })`、`Access-Control-Allow-Origin: *`) | `*` は任意オリジンに応答を読ませ、ユーザーデータを守る same-origin policy を外す | Web 以外のプロジェクト、社内 API 専用 |
| `transaction` | Medium | トランザクションラッパーなしの複数書き込み。スコープは `usecases/`、`use-cases/`、`application/`、`services/`、`domain/`、`handlers/`、`app/`、`server/` ディレクトリと `app/**/route.{ts,js}` セグメント | 書き込み途中で失敗すると部分状態が残る: 孤児レコード、残高ずれ、不変条件の崩れ | データベースを使用しないプロジェクト |
| `domAccess` | Medium | React（.tsx/.jsx）での直接 DOM 操作 | 命令的 DOM 操作は React の reconciler と競合し、不変条件が崩れて再現性の低いバグになる | React 以外のプロジェクト、またはバニラ JS/TS |
| `syncIo` | Medium | readFileSync、writeFileSync（イベントループをブロック） | 一回の同期 I/O が event loop を凍結し、並行リクエストが全てそこで詰まる | CLI ツール、ビルドスクリプト、同期のみのコンテキスト |
| `bundleSize` | Medium | lodash/moment のフルインポート | `lodash` / `moment` を丸ごとインポートすると、数個の utility のために数百 KB が全訪問者に届く | バックエンド/Node.js（バンドルサイズの懸念なし） |
| `testAssertion` | Medium | 表明が無い、または弱い表明・モック呼び出しのみ・自明な恒真のテスト | どんな出力でも通る表明（無し・toBeTruthy/toBeDefined のみ・toHaveBeenCalled のみ・expect(x).toBe(x)）は CI を green にして回帰を隠す | Playwright、カスタムテストフレームワーク |
| `flakyTest` | Low | テスト内の setTimeout、Math.random | 時刻と RNG で失敗が非決定的になり、原因究明より retry が選ばれて CI シグナルが劣化する | 意図的なタイミング/ランダムネスのテスト |
| `generatedFile` | High | \*.generated.\*、\*.g.ts の編集を警告 | 手編集は次回生成で上書きされ、修正が消える | コード生成のないプロジェクト |
| `testLocation` | Medium | src/ ディレクトリ内のテストファイル | `src/` 配下のテストは build 除外漏れで本番バンドルに混入する | コロケーションテスト戦略（ソースと同じ場所） |
| `naming` | Mixed | 命名規則。コンポーネントは Medium、interface と型は Low なので、default の閾値ではこの rule は編集を止めない | PascalCase が一貫しないと code search と、それらを識別するパターン認識を破壊する | チーム/プロジェクトで異なる命名規則がある場合 |
| `noUseEffect` | Medium | .tsx/.jsx内のuseEffectを検出し代替案を提示 | 派生 state に対する `useEffect` は余分な再 render を生み、依存配列が stale-data の罠になる | useEffectを意図的に使用するプロジェクト |
| `serviceWorker` | Medium | ルートスコープ（`{ scope: '/' }`）での Service Worker 登録。特定パスへのスコープ絞り込みを提案 | ルートスコープはオリジンの全 navigation を傍受するので、一度の誤登録でサイト全体を乗っ取られる | サイト全体に worker を意図的に配信するプロジェクト |
| `jwtClient` | Medium | クライアント側 JWT デコード（`jwtDecode`、`jwt_decode`、`atob(token.split('.'))`）。サーバー側 `jwtVerify` を推奨 | JWT payload は base64url で読めるが、署名検証なしには改竄も通る。クライアントで信用すると認可回避になる | サーバー専用 JWT デコード経路（Node 専用ファイル等） |
| `astSecurity` | Mixed | ASTベース: コマンド/正規表現/require インジェクション、スタック露出、パストラバーサル、プロトタイプ汚染、bidi 文字、env-var フォールバック、不安全な乱数、HTML インジェクション、client env leak、SSR secret bleed、postMessage origin（下記参照） | AST ベースの集約。各 sub-rule にそれぞれの脅威がある（下記 sub-rule 表を参照） | Node.js以外のプロジェクト |
| `invariant` | Mixed | 固定値ゲート: `.invariants.json` で固定したスカラー値から `.json` の値がずれる編集と、`.invariants.json` 自体の pin を弱める編集をブロック（下記参照） | 1 つの toggle に 2 つの rule_id がある。それぞれに脅威がある（下記 sub-rule 表を参照） | 不変値を固定しないプロジェクト。削除はどちらの rule でも届かない: guardrails は Write/Edit/MultiEdit の tool input のみを見るため、`rm .invariants.json` はどの hook にも届かない |
| `configGuard` | Critical | guardrails が git root で読む設定ファイル（`.guardrails.json`、`.claude/tools.json`、`.claude-guardrails.json`）への編集をブロック | 設定を書き換えられる agent は次の編集を止める rule を自分で切れる。`overrides` の追記は diff 上 test パスの除外に見える | 設定の用意を agent に任せ、人が用意できないリポジトリ |
<!-- END GENERATED: rules-table -->

### セキュリティルール（`security`）

`security` toggle 配下には 2 つの rule_id が含まれます。JSON `rule` フィールドで振り分ける consumer 向けに内訳を以下に示します。

<!-- BEGIN GENERATED: security-rules-table -->
| サブルール (rule_id) | 重大度 | 説明 | なぜ重要か |
| --- | --- | --- | --- |
| `security` | Mixed | `setTimeout('str')` / `setInterval('str')` / `postMessage(_, '*')` (High)、機密 `localStorage` / `sessionStorage` (Medium) | 文字列引数のタイマーは eval と同等、wildcard `postMessage` は任意の listener にブロードキャスト、storage 内のシークレットはオリジン上の任意スクリプトから読める |
| `dangerous-inner-html` | High | React の `dangerouslySetInnerHTML={...}`（XSS sink、`.tsx` / `.jsx` のみ対象） | React のテキストエスケープを迂回し、汚染変数が live DOM になって攻撃者のスクリプトが走る |
<!-- END GENERATED: security-rules-table -->

### ASTセキュリティルール（`astSecurity`）

[oxc](https://oxc.rs)パーサーによる深層セキュリティチェック。AST を直接解析し、正規表現ベースのパターンマッチングの偽陰性を回避します。

<!-- BEGIN GENERATED: ast-security-rules-table -->
| サブルール | 重大度 | 説明 | なぜ重要か |
| --- | --- | --- | --- |
| `child-process-injection` | High | exec/execSync/spawn/spawnSync への非リテラル引数 | 信頼できないセグメントが shell コマンドに化け、リクエスト送信者がサーバー上で任意プロセスを起動できる |
| `err-stack-exposure` | High | HTTP レスポンス（res.json/res.send）でのエラースタックトレース漏洩 | スタックでファイルパス・ライブラリバージョン・ホスティング構成が露出し、次の攻撃ステップの偵察材料になる |
| `non-literal-fs-path` | Medium | fs.\* 呼び出しでの非リテラルファイルパス（パストラバーサルリスク） | `..` セグメントが意図したルートを越えて、任意ファイルを read / overwrite できるようになる |
| `non-literal-require` | Medium | require() への非リテラル引数（動的モジュールロード） | 汚染されたモジュール名で攻撃者制御の JavaScript を実行中プロセスにロードする |
| `unsafe-regex` | Medium | ReDoS に脆弱な正規表現リテラル（ネストされた量指定子、catastrophic backtracking） | 細工した入力でエンジンが指数バックトラックに陥り、CPU が 100% になって他のリクエストに応答できなくなる |
| `bidi-characters` | High | ソース中に潜む Unicode 双方向制御文字（CVE-2021-42574 / Trojan Source） | bidi 文字は描画時にソースを並べ替えるので、レビュワーが見るコードとコンパイラが見るコードが食い違い、悪意あるロジックが平然と隠れる |
| `excessive-nesting` | High | 安全な深さを超えた入れ子 — `()[]{}` 括弧または `!`/`~` の連鎖 | 深い入れ子はパーサの再帰をオーバーフローさせ、ルール実行前にチェックプロセスを落とし、編集が黙って通ってしまう。パース前のバイトスキャンで阻止する |
| `env-var-fallback` | High | `process.env.X \|\| 'default'` 形式 — ハードコードされたフォールバックでシークレットが漏洩する | env var が未設定だとハードコードされたデフォルトが本物の credential として動き、しかもソース内に永遠に残る |
| `test-endpoint-prod-guard` | Medium | 本番ガード (`process.env.NODE_ENV === 'production'`) を持たないテスト用ルートファイル (`app/api/test-*/route.ts`、`pages/api/seed.ts` など) | 本番ガード無しのテスト専用エンドポイントは本番でデータ投入・削除・デバッグ面を露出させる。同一ファイル内のガード追加か他経路での除外確認を促す advisory |
| `prototype-pollution` | High | `Object.assign({}, untrusted)`、`_.merge`、`__proto__`/`constructor` を伴う `Object.create` | `__proto__` への書き込みがランタイム上の全オブジェクトを汚染し、認可チェックが誤動作し、sink 次第ではコード実行も開く |
| `math-random-insecure` | Mixed | トークン/ID/シークレット用途の `Math.random()`。用法が確定する場合（`toString(36)` イディオム / 暗号 API 引数）は High、命名ヒューリスティック（security 系の変数名・関数名、`toString` 他基数）止まりは Medium。詳細は [ADR-0003](docs/decisions/0003-math-random-severity-policy.md) | `Math.random` は予測可能で、これで作ったトークンは推測されセッションがハイジャックされうる |
| `unsafe-html-injection` | Mixed | `innerHTML`（High）/ `outerHTML`（Medium）/ `document.write[ln]`（High）への非リテラル代入。詳細は [ADR-0008](docs/decisions/0008-unsafe-html-injection-rule-id-separation.md) | 汚染値が HTML sink に到達すると、パーサが見つけた script タグを実行する。DOM 層での XSS |
| `client-env-public-leak` | High | `'use client'` モジュール内での `process.env.X` 参照（`NEXT_PUBLIC_*` および allow-list は除外）。Next.js によりブラウザにバンドルされる | Next.js は `process.env.*` を build 時にインライン化し、server 専用 secret がブラウザバンドルに同梱される |
| `ssr-secret-bleed` | High | `getServerSideProps` や `'use server'` Server Action が返す secret 名 (`apiKey`、`token`…) や `process.env.*` を flag。これらは Next.js がクライアントペイロードへシリアライズする | SSR の返り値は HTML payload にシリアライズされ、認証していない訪問者を含む全員に secret が届く |
| `postmessage-origin-missing` | High | `window.addEventListener('message', handler)` のインラインハンドラが `event.origin` を読まない場合。origin チェックなしでは任意の sender からのクロスオリジン postMessage を受け入れてしまう。外部ハンドラ参照やパラメータ側 destructure は 1-file static analysis の範囲外 | 埋め込まれた iframe や popup から送られたメッセージをハンドラが信用し、ページが攻撃者の選んだコマンドを実行してしまう |
<!-- END GENERATED: ast-security-rules-table -->

### 不変値ルール（`invariant`）

`invariant` toggle には 2 つの rule_id があります。片方は固定した値そのものを守り、もう片方はそれを宣言したファイルを守ります。

<!-- BEGIN GENERATED: invariant-rules-table -->
| サブルール (rule_id) | 重大度 | 説明 | なぜ重要か |
| --- | --- | --- | --- |
| `invariant` | High | `.invariants.json` で固定したスカラー値から `.json` の値がずれる編集をブロック（feature flag、i18n 文言、design token） | 固定値はアプリ全体が依存する契約で、無言で変える編集は誰も承認していない挙動変更を出荷する |
| `invariant-guard` | Critical | `.invariants.json` 自体への編集が宣言済み pin を落とす、または宣言値を変えるものであれば、上記のドリフト検知とは独立にブロック | 宣言ファイルを書き換えられる agent は、pin が守ろうとしているファイルに触れずに pin 自体を弱められる。上記のドリフト検知はこれを検出できない |
<!-- END GENERATED: invariant-rules-table -->

## サブコマンド

```text
Usage: guardrails [OPTIONS] [COMMAND]

Commands:
  prefetch  Download oxlint binary into the cache (no-op if already present)
  help      Print this message or the help of the given subcommand(s)

Options:
      --json     Emit a structured JSON envelope on stdout (hook violations or prefetch result)
  -h, --help     Print help
  -V, --version  Print version
```

サブコマンドなしで `guardrails` を呼ぶと**hook モード**（stdin から tool_input JSON を読む）になります。`guardrails --help` で終了コードを含む完全な説明を表示できます。

## 終了コード

Claude Code は終了コードを見て、tool 呼び出しを通す/AI に警告を見せる/停止するを決めます。PreToolUse 契約で呼び出しを止めるのは exit `2` のみ。`0` は通過、`1`/`64` は非 blocking (tool は続行) です。stderr が AI に届くのは exit `2` のときだけで、advisory の検出結果は stdout の PreToolUse hook JSON で AI に渡ります。検査の途中で panic した場合も exit `2` を返し、検査未完了の編集を素通りさせず fail-closed にします。

### hook モード (サブコマンドなし)

| コード | 意味                                                                                                                                               |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0      | 合格 — 違反なし                                                                                                                                    |
| 1      | 警告のみ — 非 blocking severity 違反、tool は実行され、検出結果は stdout の hook JSON で AI に渡る                                                 |
| 2      | ブロック — `severity.blockThreshold` (デフォルト: `high`) 以上の違反、サイズ超過 stdin、または検査途中の panic (いずれも fail-closed)、tool を停止 |
| 64     | hook 入力エラー — JSON 不正、stdin read 失敗、または clap usage 失敗 (非 blocking)                                                                 |

### サブコマンド (`prefetch`)

| コード | 意味                                              |
| ------ | ------------------------------------------------- |
| 0      | 成功                                              |
| 64     | 使用方法エラー (clap parse 失敗)                  |
| 65     | データエラー (非対応プラットフォーム)             |
| 74     | I/O エラー (ネットワーク / 展開 / キャッシュ失敗) |

> **BREAKING (v0.16+)**: 非 blocking severity 違反 (`severity.blockThreshold` 未満) は exit `1` を返すようになりました (旧 `0`)。hook stdin / JSON / サイズ超過 失敗は exit `64` (旧 `1` または `2`)。内部 panic は exit `70`。JSON の `decision` フィールド (`allow` / `block`) は変わりません — 引き続き blocking 違反のみを判定します。

> **BREAKING (v0.21+)**: サイズ超過 stdin (10 MB 上限超) は exit `64` でなく `2` (block) を返すようになりました。exit `64` は PreToolUse 呼び出しを止めないため、旧 `64` ではサイズ超過 payload が素通りしていました。`2` でリソース境界 guard が fail-closed になります。JSON 不正と stdin read 失敗は `64` のまま (非 blocking、設計上の fail-open) です。

> **BREAKING (v0.21+)**: hook モードの検査中の panic は exit `70` でなく `2` (block) を返すようになりました。exit `70` は PreToolUse 呼び出しを止めないため、旧 `70` では検査途中の panic が未検査の編集を素通りさせていました。`2` で fail-closed になります。exit `70` は `prefetch` と隠し AST-child サブコマンドの内部 panic に残ります。

> **BREAKING (v0.17+)**: `severity.blockOn` (配列) は `severity.blockThreshold` (単一の severity) に置き換わりました。閾値以上の違反が blocking、未満が警告になります。デフォルト `"high"` は旧 `["critical", "high"]` と等価です。未知の `blockOn` キーは silent に無視されるため、`medium` や `low` を列挙していた config は `"blockThreshold": "medium"` / `"low"` に移行してください。まれな `blockOn: []` (何もブロックしない) に代替はありません。

## JSON 出力モード

`--json` フラグを渡すと stdout に構造化された JSON レポートを出力します。人間向けの出力は stderr に残り、終了コードも変わりません。Claude Code などのエージェントが安定したパース可能な契約を必要とするケースを想定しています。

```sh
guardrails --json < tool-call.json
```

> **BREAKING (v0.15+)**: v0.14 で利用できた `GUARDRAILS_JSON=1` env は削除されました。代わりに `--json` を使ってください。

> **hook の `command` に `--json` を足さないでください。** stdout に出る document は 1 つで、`--json` のときは envelope、そうでないときは advisory を AI へ届ける PreToolUse hook JSON です。hook にフラグを足すとこの配送が止まります。`--json` は guardrails を直接読むツール向けです。

> **BREAKING (v0.15+)**: 成功時の出力は[ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md)に従って `SuccessEnvelope` (`{ data, degraded, notes }`) で wrap されます。旧 schema (`{ violations, decision, exit_code }`) は廃止 — hook 判定はプロセス終了コードを参照してください。

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

| フィールド        | 型                                             | 補足                                                                                                                                                                                          |
| ----------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data.violations` | 配列                                           | ブロッキングと警告の両方を含む。`severity` で区別可能                                                                                                                                         |
| `data.decision`   | `"block"` / `"allow"`                          | `severity.blockThreshold` 以上のエントリがある場合のみ `block`                                                                                                                                |
| `severity`        | `"critical"` / `"high"` / `"medium"` / `"low"` | 小文字                                                                                                                                                                                        |
| `line`            | 整数または `null`                              | 位置が不明な場合は `null`                                                                                                                                                                     |
| `origin`          | `"introduced"` / `"preexisting"` (optional)    | `diffAware` on のときのみ付く。`preexisting` は編集前から存在して降格された違反、それ以外の報告は `introduced`。toggle off ではフィールド自体が省略される ([diffAware](#diffaware)参照)       |
| `degraded`        | bool                                           | note が 1 件でもあれば `true`。環境系の note (project root canonicalize 失敗 / config load 失敗 / oxlint 不在) と post-edit content fallback の note を union する。原因は必ず `notes` を読む |
| `notes`           | 文字列の配列                                   | degrade の理由。source 順 (project root → config → linter → content fallback) で並び、dedup しない。non-empty なら `degraded: true`                                                           |

### Error envelope

`--json` 設定時に stdin が不正な場合、stdout に `ErrorEnvelope` が出力されます。malformed JSON/IO 失敗は終了コード `64` (hook input error、非 blocking)、oversized (10 MB 上限超) は終了コード `2` (block、fail-closed) で終了します。

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

| フィールド         | 型                                              | 補足                                                                                              |
| ------------------ | ----------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `error.code`       | `"USAGE_ERROR"` / `"DATA_ERROR"` / `"IO_ERROR"` | [ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md)準拠の SCREAMING_SNAKE_CASE |
| `error.message`    | string                                          | 人間向けの詳細 (stderr にも出力される)                                                            |
| `error.next_step`  | string (optional)                               | 復旧のための具体的なアクション                                                                    |
| `error.candidates` | 文字列の配列 (optional)                         | 復旧候補 (空なら省略)                                                                             |
| `error.retryable`  | bool                                            | 一時的な失敗の場合のみ `true`                                                                     |

> **ケース混在**: `severity` は小文字 (v0.14 からの継承) で `error.code` は SCREAMING_SNAKE_CASE ([ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md))。意図的な混在で、両 shape は安定しています。

`--json` を付けない場合、出力は人間向けデフォルトモードとバイト単位で完全互換です。

## 設定

プロジェクトルートに `.guardrails.json` を配置します。フォーマットは flat な `ProjectConfig` スキーマ（`guardrails` キーで包まない）。すべてのフィールドはオプションで、オーバーライドしたいもののみ指定してください。これは agent-neutral な path で、Claude Code、codex CLI、その他の AI agent から guardrails を hook として実行する場合のいずれでも同じように動作します。

> **その他の対応 path**:
>
> - `.claude/tools.json`（`guardrails` キー配下に設定）— Claude Code の 4-tool pipeline 規約。`.guardrails.json` 不在時に使われる
> - `.claude-guardrails.json` — レガシーフォールバック。上記いずれも見つからない場合に使われる
>
> 複数 file が存在する場合、優先順位は `.guardrails.json` > `.claude/tools.json` > `.claude-guardrails.json`。最初に見つかった 1 つだけが読み込まれます。

設定ファイルがない場合のデフォルト構成です。

- すべてのルールが有効
- `critical`と`high`の重大度でブロック

### スキーマ

`.guardrails.json`（推奨、agent-neutral）:

```json
{
  "enabled": true,
  "diffAware": false,
  "rules": {
    "oxlint": true,
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": true,
    "eval": true,
    "hardcodedSecrets": true,
    "cotLeakageMarker": true,
    "openRedirect": true,
    "rawHtml": true,
    "sqliConcat": true,
    "httpResource": true,
    "corsWildcard": true,
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
    "serviceWorker": true,
    "jwtClient": true,
    "astSecurity": true,
    "invariant": true,
    "configGuard": true
  },
  "oxlint": {
    "deny": [],
    "allow": []
  },
  "severity": {
    "blockThreshold": "high"
  },
  "overrides": []
}
```

`.claude/tools.json` で記述する場合は、上記オブジェクト全体を `"guardrails"` キーで包んでください（4-tool pipeline 規約）。

#### `oxlint.deny` / `oxlint.allow`

deny リストにルールを追加、またはデフォルト deny から除外できます。

```json
{
  "oxlint": {
    "deny": ["eslint/curly"],
    "allow": ["eslint/no-console"]
  }
}
```

- `deny`: `--deny` で追加有効化するルール（デフォルトとマージ）
- `allow`: deny リストから除外するルール（例: CLI プロジェクトで `console.log` を許可）

#### `diffAware`

デフォルト off。有効にすると、すでにブロッキング違反を含むファイルへの編集では、その編集が新規に持ち込んだ違反だけをブロックします。編集前から存在した違反は警告 (exit 1) に降格するため、無関係な修正が過去の違反に塞がれません。

```json
{
  "diffAware": true
}
```

- 降格の対象は、報告された 1 行だけで違反が完全に決まるルールに限定されます (現在は `eval` のみ)。それ以外のルールと oxlint 移譲の違反は、編集前から存在してもブロックを維持します。
- 照合は (ルール, trim 済み行テキスト) の個数で行うため、既存の違反行をもう 1 つ複製した場合、増えた分はブロックされます。
- フェイルセーフ: 編集前の状態を信頼できない場合 (読み取り不能、編集解決の degrade、編集前 content の parse 失敗) は降格全体を中止し、すべての違反がブロックを維持、`demotion skipped (...)` の note が原因を示します。新規ファイルの Write は失敗ではなく、含まれる違反はすべて新規としてブロックされ、note は付きません。
- toggle on のとき、JSON 出力の各違反に `"origin": "introduced"`/`"origin": "preexisting"` が付き、降格された警告は stderr で `(preexisting)` と表示されます。toggle off では `origin` フィールド自体が出力されず、従来とバイト互換です。

#### `overrides`

パス単位のルール toggle です。パスが glob にマッチした file に対して、top-level の `rules` の上にこの toggle を重ねます。形は ESLint の `overrides` と同じで、`{ files, rules }` の配列。各 `rules` は変更したいキーだけを持つ部分オブジェクトです。

```json
{
  "overrides": [
    {
      "files": ["src/**/*.test.ts", "src/**/*.spec.ts"],
      "rules": {
        "testAssertion": false
      }
    }
  ]
}
```

- `files`: glob pattern は絶対パスや cwd 相対パスではなく、git root からの相対パスに対してマッチします。`*`/`?` は `/` を跨がないため、`src/*.ts` は `src/app.ts` にマッチしますが `src/api/db.ts` にはマッチしません。globset のデフォルト（`/` を跨ぐ）ではなく ESLint の glob 挙動に揃えています（[globset `literal_separator`](https://docs.rs/globset/0.4.20/globset/struct.GlobBuilder.html#method.literal_separator)）。`../` などで git root の外へ出る file_path はどの override にもマッチしません。
- `rules`: top-level の `rules` オブジェクトと同じキーです（上記の[ルール](#ルール)参照）。指定しなかったキーは、この entry にマッチした file でも top-level（またはデフォルト）の値のままです。
- 同じ file に複数の entry がマッチした場合、配列の順序どおりに適用され、キー単位で merge されます。後続の entry は名指ししたキーだけを上書きし、先行の entry が設定した `rules` オブジェクト全体を置き換えることはありません。
- `files` の pattern が glob として compile できない entry（閉じ括弧を欠いた `[` など）は、その entry ごと丸ごと捨てられます。同じ config の他の `overrides` entry と top-level の `rules` は影響を受けません。guardrails は compile できなかった pattern を名指しした note を積みます。例: `override entry dropped: glob pattern "src/[invalid" failed to compile`。この note は、チェック対象の file が該当 entry の `files` にマッチするかどうかに関わらず、config を読み込むたびに JSON envelope の `notes` と stderr の両方に出ます。
- toggle の粒度であり、rule の粒度ではありません。override の `rules` キーは top-level と同じ粗さの toggle で、個々の `rule_id` 単位ではありません。ある glob に対して `security` や `astSecurity` を無効化すると、その toggle が束ねる `rule_id` がマッチした file すべてで一括して無効になります。`astSecurity` の場合は上記の AST セキュリティルールに載る 15 行のうち 14 個で、1 個だけを選ぶことはできません。他の sub-rule を有効なまま残しつつ 1 個だけをパス単位で切る手段はありません。
- `excessive-nesting` だけは override で切れません。この sub-rule は AST rule のどれか 1 つでも有効なときにパース前のバイトスキャンとして走ります。`astSecurity` で gate すると、`astSecurity` が off で `eval` が on の config がパーサに到達してプロセスを落とすためです。`astSecurity` を無効化する override を書いても、安全な深さを超えた入れ子の file は block されます。
- `security` を override で無効化しても、`postMessage(_, '*')` の wildcard origin 検査は止まりません。この検査は rule_id `security` で発火しますが、実体は `astSecurity` 側の `analysis::ast_security::postmessage::check_post_message_wildcard` で、`security` toggle とは独立に走ります。`security` だけを off にした glob でも `astSecurity` が有効な限り検出は続き、両方を off にして初めて止まります。
- override がチェック対象の file に対してルールを無効化すると、guardrails は無効化したルール名とマッチした pattern を記した note を積みます。例: `override disabled rule(s) [testAssertion] for pattern(s) [src/**/*.test.ts]`。この note は JSON envelope の `notes` と stderr の両方に出ます。
- pattern は symlink を解決した後のパスにマッチします。`src/allowed/esc` が `../protected` を指す symlink のとき、`src/allowed/esc/app.ts` への Write は `src/protected/app.ts` として判定され、`src/allowed/**` の override は当たりません。解決でパスが変わった場合は note が出ます。例: `override matching followed a symlink: /repo/src/allowed/esc/app.ts resolves to src/protected/app.ts`。まだ存在しないディレクトリを含むパスは、最も近い実在の祖先まで遡って解決します。
- hook が判定してから実際の書き込みが起きるまでの間に symlink を差し替える操作は対象外です。guardrails は書き込み前の 1 回しか呼ばれません。

### 設定例

デフォルト構成（設定ファイル不要）。全ルール有効、oxlint 自動確保、AI 向け deny ルール有効。

カスタムルールのみの構成（oxlint 無効）。

```json
{
  "rules": {
    "oxlint": false
  }
}
```

バックエンド（Node.js/API）向け。フロントエンド固有ルール無効化、console 許可。

```json
{
  "rules": {
    "domAccess": false,
    "bundleSize": false
  },
  "oxlint": {
    "allow": ["eslint/no-console"]
  }
}
```

すべての重大度でブロックする構成（`low` が下限なので閾値が全てをブロック）。

```json
{
  "severity": {
    "blockThreshold": "low"
  }
}
```

プロジェクト単位で guardrails を無効化。

```json
{
  "enabled": false
}
```

特定 directory だけルールを緩める。

```json
{
  "overrides": [
    {
      "files": ["fixtures/**"],
      "rules": {
        "testAssertion": false
      }
    }
  ]
}
```

`testAssertion` は他の場所では有効なまま。`fixtures/` 配下の file だけがこのルールをスキップします。

### 設定の解決

対象ファイルからもっとも近い `.git` ディレクトリまで上方向に探索されます。次の順序で最初に見つかった file のみが読み込まれます。

```text
project-root/
├── .guardrails.json         ← 推奨（agent-neutral、flat スキーマ）
├── .claude/
│   └── tools.json           ← Claude Code 4-tool pipeline（guardrails キー）
├── .git/
├── src/
│   └── app.ts               ← チェック対象ファイル → 上方向に設定を探索
└── .claude-guardrails.json  ← レガシーフォールバック
```

## 既存リンターとの併用

lefthook、husky、lint-staged 経由で oxlint をコミット時に実行している場合、guardrails のリンターチェックと重複する可能性がありますが、両者の目的は異なります。

| ツール            | タイミング         | 目的                           |
| ----------------- | ------------------ | ------------------------------ |
| guardrails (hook) | ファイル書き込み時 | 問題が書き込まれる前に防止     |
| lefthook / husky  | コミット時         | コード履歴に入る前の最終ゲート |

oxlint を guardrails で無効化し、コミットフックに任せる場合の設定です。

```json
{
  "rules": {
    "oxlint": false
  }
}
```

これにより guardrails のカスタムセキュリティルール（sensitiveFile、cryptoWeak 等）を有効に保ちつつ、リンターの重複チェックを回避できます。

## 既知の制限事項

### 行ベースルール（architecture、security、cryptoWeak等）

これらのルールは `non_comment_lines()` を使用し、`/* ... */` ブロックコメントの状態を行間で追跡しつつ `//` 行コメントをフィルタリングします。

- **`/*`や`*/`を含む文字列リテラル** — リテラル内のコメントマーカー（例: `let s = "/* not a comment */";`）を実際のコメント境界として扱い、誤ったフィルタリングを引き起こす可能性がある
- **行頭のアスタリスク** — `*`で始まる行は JSDoc の継続行として扱われる

### スキャナーベースルール（sensitiveLogging、testAssertion）

これらのルールは行間でコメント状態を追跡する `StringScanner` を使用します。

- **JavaScript正規表現リテラル** — `//`や`/*`を含むパターン（例: `/https:\/\//`）がコメント開始として誤認識される可能性がある

これらのトレードオフは、偽陰性よりも偽陽性が望ましい guardrails のユースケースにおいて許容範囲です。

### ファイル拡張子のスコープ

JS 解析 (oxlint、AST、ast-security) の対象は `.js`、`.ts`、`.jsx`、`.tsx`、`.mjs`、`.mts` です。CommonJS の `.cjs`/`.cts` は対象外です。これらはフロントエンドコードではなく、ビルド設定・CLI・ジェネレータ等の Node ツーリングが主だからです。

## 関連ツール

| ツール                                         | Hook        | タイミング              | 役割                          |
| ---------------------------------------------- | ----------- | ----------------------- | ----------------------------- |
| **guardrails**                                 | PreToolUse  | Write/Edit 前           | リント + セキュリティチェック |
| [formatter](https://github.com/thkt/formatter) | PostToolUse | Write/Edit 後           | 自動コード整形                |
| [reviews](https://github.com/thkt/reviews)     | PreToolUse  | レビュー系 Skill 実行時 | 静的解析コンテキスト提供      |
| [gates](https://github.com/thkt/gates)         | Stop        | エージェント完了時      | 品質ゲート (knip/tsgo/madge)  |

## ライセンス

MIT
