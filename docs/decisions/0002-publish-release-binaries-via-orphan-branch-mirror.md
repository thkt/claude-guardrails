---
status: "accepted"
date: 2026-05-13
decision-makers: thkt
---

# Publish release binaries to sentinels via orphan-branch mirror

## Context and Problem Statement

guardrails は GitHub Releases + Homebrew で配布しており、sentinels marketplace 経由で `claude plugins install` した直後に `install.sh` が走り、curl/wget で GitHub Releases からバイナリを取得する。このフローは初回 install 時にネットワーク必須で、GitHub Releases 障害時には install 自体が失敗する。`claude plugins install` で marketplace clone した状態でそのまま実行可能にしたい。同じ問題は formatter / reviews / gates にも当てはまるため、配布方式は 4 ツール共通フローとして設計する必要がある。

ADR-0001 は guardrails の release tarball に oxlint を同梱する案を却下した。本 ADR は配布チェーンの段が異なる別議論 (guardrails 等のツール本体を sentinels に同梱) であり、上流 oxc プロジェクトのライブラリ API 不在のような外部制約は本件では存在しない。

## Decision Drivers

* First-run UX: `claude plugins install` 直後に追加ダウンロードなしで実行可能にしたい
* Availability: GitHub Releases ダウン時に install が落ちない経路を持ちたい
* Repository size: sentinels リポの容量を GitHub の soft limit (1 GB) 内に保つ
* Clone overhead: `claude plugins install` 側に追加コストを乗せない
* 共通フロー: guardrails / formatter / reviews / gates の 4 ツール共通の枠組みにする (個別解にしない)
* Backward compatibility: GitHub Releases / Homebrew の既存配布経路は維持する
* Reversibility: 採用を 1 PR で巻き戻せること

## Considered Options

* A: sentinels の main branch に `{tool}/bin/` を直接 commit する
* B: Git LFS で sentinels の main branch に置く
* C: sentinels の GitHub Releases tarball に同梱する
* D: sentinels の orphan branch (`binaries`) に置き、毎リリース force push で履歴を 1 コミットにリセットする
* E: 現状維持 (GitHub Releases + Homebrew のみ)

## Decision Outcome

Chosen option: **D (orphan branch + force push reset)**.

理由は次の 3 つを同時に満たすため:

1. `claude plugins install` は shallow clone であることをインストール済み marketplace の作業ツリーで確認している (`.git/shallow` の存在、`.git` ディレクトリ実測 132 KB)。main 履歴がいくら膨らんでも install 側のオーバーヘッドにならない一方、orphan branch の force push で remote 側の容量も一定に保てる
2. binary は main の履歴を汚さず、ツール開発者が main を full clone した時の負担も最小化される
3. Git LFS のような quota / 別途 `git lfs pull` を必要としない、git client 標準機能のみで成立する

### Consequences

* Good, because `claude plugins install` 直後の追加ダウンロードが不要 (binaries branch を install.sh が shallow fetch するだけ)
* Good, because sentinels remote の容量が「最新 1 リリース分 × ツール数」で頭打ちになる (orphan reset により)
* Good, because main branch 履歴は binary を含まずクリーンに保たれる
* Good, because guardrails / formatter / reviews / gates に同じパターンを適用できる (CI job は TOOL / REPO 変数化可能)
* Good, because GitHub Releases / Homebrew 経路は変更なしで併存し、fall-through できる
* Bad, because install.sh に「binaries branch を fetch して該当ツールの bin を取り出す」処理が増える
* Bad, because force push を運用に組み込むため、binaries branch を別用途で参照することはできない
* Bad, because sentinels 側の git history は force push されるが、これは binaries branch のみで main branch は影響を受けない

### Confirmation

実装は 2 リポジトリにまたがる。

**In `thkt/guardrails` (this repo)**

* `.github/workflows/release.yml` に `publish-binaries-to-sentinels` job を追加し、`update-sentinels` の後段で動かす
* job が darwin arm64/x64 + linux arm64/x64 の 4 platform tarball を sentinels の `binaries` orphan branch に force push する
* タグ push で実際に sentinels の `binaries` branch が想定通り更新されることをリリース時に確認

**In `thkt/sentinels` (plugin distribution, 別 issue で追跡)**

* `shared/hooks/install-lib.sh` が `binaries` branch を fetch して `bin/{tool}-{platform}.tar.gz` を優先利用する経路を追加
* fall-through として GitHub Releases ダウンロード経路は残す
* End-to-end: 新規環境で `claude plugins install` 直後の `~/.local/bin/guardrails` 存在を確認

## Pros and Cons of the Options

測定値ベース (release ビルド済みバイナリと sentinels リポ作業ツリーへの `ls -la` / `du -sh` で実測):

* guardrails release バイナリ: 4.0 MB (`target/release/guardrails`)
* sentinels リポ `.git` ベースライン: 1.1 MB
* `claude plugins install` 直後のインストール側 sentinels `.git`: 132 KB (`.git/shallow` 存在を確認)
* guardrails リリース実績: 19 リリース (v0.0.x〜v0.14.1)
* 4 platform tarball / リリース: 約 16 MB (4 MB × 4)

### A: main branch に直接 commit

毎リリース `{tool}/bin/*.tar.gz` を main に上書き commit する。

* Good, because 実装が一番シンプル (CI は普通の commit & push のみ)
* Good, because shallow clone 前提なら install 側は履歴肥大の影響を受けない
* Bad, because remote 側 main の `.git/objects` が 4 ツール分蓄積する: 4 ツール × 16 MB × 50 リリース/年 = 3.2 GB/年 で GitHub の soft limit 1 GB を 1 年以内に超える
* Bad, because main 履歴を full clone するツール開発者は使い物にならない規模に到達する
* Bad, because 一度蓄積した履歴の縮小は git filter-repo 等の不可逆操作になる

### B: Git LFS で main branch に置く

binary を LFS pointer file として main に置き、実体は GitHub LFS storage に保存する。

* Good, because main の `.git/objects` は pointer サイズしか増えない
* Good, because shallow clone との相性は良い (LFS pointer は通常の blob として扱われる)
* Bad, because GitHub Free の LFS quota は storage 1 GB / 帯域 1 GB/月 で、4 ツール × 16 MB × 50 リリース = 3.2 GB/年 の storage と install 側からの pull 帯域で破綻する。Pro / data pack 課金が前提になる
* Bad, because `claude plugins install` が LFS pull を自動で行う保証がない。`git clone --depth 1` 直後は LFS pointer のままで、別途 `git lfs pull` が必要になるケースがある (要検証だが、依存を増やす方向)
* Bad, because install 側に `git-lfs` バイナリ要件が増える

### C: sentinels の GitHub Releases tarball に含める

sentinels 側で release tarball を作り、その中に各ツールの binary を入れる。

* Bad, because `claude plugins install` は marketplace を git clone するため、GitHub Releases tarball は使われない (issue 自身が指摘済み)
* この案は最初から「marketplace install で取れない」ため要件を満たさず、検討対象として記録するに留める

### D: orphan branch + force push reset

sentinels に `binaries` orphan branch を作り、毎リリース「binaries branch を捨てて新しい orphan として作り直し → force push」する。main は触らない。

* Good, because main branch 履歴を一切汚さない (ツール開発者の full clone 負担ゼロ)
* Good, because binaries branch の `.git/objects` は常に「最新 1 コミット分 = 4 ツール × 16 MB = 64 MB」で頭打ちになる
* Good, because shallow clone と相性が良い (`git fetch --depth=1 origin binaries:binaries` で 64 MB だけ取得すれば良い)
* Good, because LFS quota や追加 binary 依存を必要としない
* Good, because TOOL / REPO 変数化で 4 ツール共通の reusable job として実装できる
* Bad, because install.sh に「binaries branch を fetch して bin を取り出す」処理が増える (50 行程度の追加と想定)
* Bad, because main branch から見た時に「binaries は履歴を持たない」という認知コストが少しある (運用ドキュメントで吸収)

### E: 現状維持

GitHub Releases + Homebrew のみで配布し、install.sh は引き続き curl/wget でダウンロードする。

* Good, because 追加実装ゼロ
* Bad, because issue が指摘する 3 つの問題 (初回ネットワーク必須 / GitHub Releases 障害耐性 / marketplace clone だけで実行可能にしたい) を一切解決しない

## More Information

### Implementation Plan

実装は 2 リポジトリにまたがる。

**In `thkt/guardrails` (this repo)**

1. `.github/workflows/release.yml` に `publish-binaries-to-sentinels` job を追加し、`needs: release` で `update-sentinels` と並列に動かす (相互依存なし)
2. job の処理は次の流れ (subtree 差し替え + orphan reset 方式):
   * `actions/checkout` で sentinels リポを取得 (token: `SENTINELS_TOKEN`)
   * `git fetch --depth=1 origin binaries 2>/dev/null` で既存 binaries branch を取得 (失敗 = 初回 push)
   * 既存 binaries branch がある場合は worktree に展開 (`git worktree add` or `git checkout`) して他ツールのファイル群 (`formatter/`, `reviews/`, `gates/` など) を一時保全
   * `actions/download-artifact` で build job のアーティファクトを取得 (`pattern: guardrails-*-darwin-*` および `guardrails-*-linux-*` で Windows 除外)
   * 取得した 4 platform tarball を `guardrails/bin/` 配下に配置 (この時点で他ツールのファイル群は隣に保存済み)
   * `git checkout --orphan binaries-new` → 全ファイル (他ツール + 更新版 guardrails) を `git add` → `git commit` → 既存 binaries branch を削除 → リネーム → `git push -f origin binaries`
   * commit message: `binaries: guardrails v${VERSION}`
3. concurrency group `publish-binaries-to-sentinels` を設定し、`update-sentinels` と direct conflict しないが同時 push を直列化する
4. 将来的に他ツールも同じ pattern を踏襲できるよう、TOOL / REPO / PLATFORMS を env で集約する (`workflow_call` 化の前段)
5. orphan reset によって binaries branch の history は常に 1 commit に保たれ、subtree 差し替えによって他ツールのバイナリも保全される (容量頭打ち + 多ツール共存の両立)

**In `thkt/sentinels` (plugin distribution, 別 issue)**

1. `shared/hooks/install-lib.sh` の `install_tool` に「binaries branch から fetch」フローを前置:
   * marketplace clone の作業ツリー上で `git fetch --depth=1 origin binaries 2>/dev/null` を試行
   * 成功時は `git show binaries:${TOOL}/bin/${asset}` で tarball を取り出して既存抽出ロジックに渡す
   * 失敗時は既存の curl/wget ダウンロード経路にフォールバック
2. fallback 順序: ローカルキャッシュ (binaries branch) → GitHub Releases → Homebrew、ではなく、既存の Homebrew 優先を維持しつつ "Homebrew 未インストール時の curl ダウンロード" の前段に binaries branch fetch を差し込む

### Rollback Plan

* guardrails 側: `release.yml` から `publish-binaries-to-sentinels` job ブロックを削除するだけで CI は元の経路に戻る (PR 1 本の revert で完結)
* sentinels 側: `install-lib.sh` の binaries fetch ブロックを削除すれば、`install.sh` は既存の curl/wget 経路で動作を続ける
* binaries branch 自体は force push で空 commit を 1 つ置くか branch ごと削除する (履歴を持たないため迷う必要はない)

### Reassessment Triggers

* `claude plugins install` の clone 仕様が将来変更され shallow でなくなった場合 → 全方式を再評価
* sentinels の binaries branch fetch が install 体験の bottleneck になった場合 → A 案 (main 直 commit + GitHub の `git gc` 任せ) や release tarball + 別経路への切り替えを再評価
* GitHub LFS が無料枠を大幅に拡張した場合 → B 案を再評価
* ツール数が増えて 1 リリースあたりの binaries サイズが 500 MB を超える見込みになった場合 → 分割配布 or platform 別 branch を再評価

### References

* `.github/workflows/release.yml:192-228` — 現状の `update-sentinels` job (plugin.json バージョン同期のみ)
* `thkt/sentinels:shared/hooks/install-lib.sh:39-81` — 現状の `install_tool` (curl/wget ダウンロード)
* `claude plugins install` 後の marketplace 作業ツリーに `.git/shallow` ファイルが存在 — shallow clone の根拠
* ADR-0001 — guardrails release tarball への oxlint 同梱却下 (本 ADR は配布チェーンの段が異なる別議論)
* GitHub repository size limits: <https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github>
