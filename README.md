**English** | [日本語](README.ja.md)

# guardrails

Code quality checker for Claude Code's PreToolUse hook. Combines external linters with custom rules to validate code and provide actionable fix suggestions.

## Features

- **oxlint auto-provision**: Automatically resolves or downloads [oxlint](https://oxc.rs) — no manual install needed
- **AI-tuned deny rules**: Enables `no-explicit-any`, `ban-ts-comment`, `no-non-null-assertion`, `no-console`, `no-new-func` by default via `--deny`
- **Custom rules**: Security patterns external linters don't cover (JS/TS)
- **AST-based security checks**: Deep analysis via [oxc](https://oxc.rs) parser (command injection, stack exposure, path traversal)
- **Claude-optimized output**: Actionable fix suggestions in stderr

## Installation

### Claude Code Plugin (Recommended)

Installs the binary and registers the hook automatically:

```bash
claude plugins marketplace add thkt/sentinels
claude plugins install guardrails
```

If the binary is not yet installed, run the bundled installer:

```bash
~/.claude/plugins/cache/guardrails/guardrails/*/hooks/install.sh
```

### Homebrew

```bash
brew install thkt/tap/guardrails
```

### From Release

Download the latest binary from [Releases](https://github.com/thkt/guardrails/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/guardrails/releases/latest/download/guardrails-aarch64-apple-darwin.tar.gz | tar xz
mv guardrails ~/.local/bin/
```

### From Source

```bash
cd /tmp
git clone https://github.com/thkt/guardrails.git
cd guardrails
cargo build --release
cp target/release/guardrails ~/.local/bin/
cd .. && rm -rf guardrails
```

## Usage

### As Claude Code Hook

When installed as a plugin, hooks are registered automatically. For manual setup, add to `~/.claude/settings.json`:

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

## Requirements

No external linter installation required. guardrails automatically resolves oxlint:

1. `node_modules/.bin/oxlint` (project-local)
2. `oxlint` on `PATH` (global install)
3. `~/.cache/guardrails/bin/oxlint-{version}` (cached download)
4. Auto-download from GitHub Releases (first run only)

If all resolution steps fail (e.g., no network), guardrails continues with custom rules only (fail-open).

| Condition        | Linter used       |
| ---------------- | ----------------- |
| oxlint found     | oxlint + custom   |
| oxlint not found | Custom rules only |

Project config files (`oxlintrc.json`) are automatically used when present.

### Prefetch

`guardrails prefetch` runs steps 3–4 of the resolution chain eagerly: if oxlint is already cached or PATH-resolvable, it exits without network activity; otherwise it downloads from GitHub Releases.

```bash
guardrails prefetch
```

Use it to:

- Pre-stage oxlint at install time so the first `Write`/`Edit` doesn't pay the download latency
- Warm the cache in CI before tests run
- Pre-stage on a connected machine for air-gap deployment (then copy `~/.cache/guardrails/bin/`)

| Outcome                                                    | Exit | `error.code` |
| ---------------------------------------------------------- | ---- | ------------ |
| Already cached or downloaded successfully                  | 0    | (none)       |
| Unsupported platform (e.g. Windows / non-amd64)            | 65   | `DATA_ERROR` |
| Network failure (download / read error)                    | 74   | `IO_ERROR`   |
| Extract failure (tar / cache write / rename)               | 74   | `IO_ERROR`   |
| Cache directory unavailable (no `XDG_CACHE_HOME` / `HOME`) | 74   | `IO_ERROR`   |

> **BREAKING (v0.15+)**: `prefetch` exit codes changed from `0` / `1` to sysexits.h values (`0` / `65` / `74`). Pass `--json` to receive a structured `ErrorEnvelope` (`{ error: { code, message, next_step, retryable } }`) on failure.

### AI-Tuned Deny Rules

guardrails enables these oxlint rules via `--deny` (off by default in oxlint, important for AI-generated code):

| Rule                               | Why                                          |
| ---------------------------------- | -------------------------------------------- |
| `typescript/no-explicit-any`       | AI uses `any` / `as any` to bypass types     |
| `typescript/ban-ts-comment`        | AI uses `@ts-ignore` to suppress errors      |
| `typescript/no-non-null-assertion` | AI uses `!` to skip null checks              |
| `eslint/no-console`                | AI leaves debug `console.log`                |
| `eslint/no-new-func`               | AI uses `new Function(...)` for dynamic code |

> **Note:** `new Function(...)` triggers both oxlint's `eslint/no-new-func` (High via `--deny`) and the custom `eval` rule (High), so the agent reads the guardrails-specific fix message even after oxlint already fired. stderr shows oxlint first.

Customize via `oxlint.deny` / `oxlint.allow` in config (see below).

## Custom Rules

See `src/rules/` for custom rules that complement external linters.

### Rules

<!-- BEGIN GENERATED: rules-table -->
| Rule | Severity | Description | Why it matters | When to disable |
| --- | --- | --- | --- | --- |
| `sensitiveFile` | Critical | Blocks writes to .env, credentials.\*, \*.pem | Committed credentials persist in git history and CI logs and have to be rotated to revoke | Never (security critical) |
| `cryptoWeak` | High | Detects MD5, SHA1, DES, RC4 usage | Collisions and key recovery are feasible; the primitive cannot deliver the guarantee it promises | Legacy system maintenance with known constraints |
| `sensitiveLogging` | High | Detects password/token/secret in console.log | Logs flow into CI runners, monitoring sinks, and crash reporters, so every downstream reader sees the secret | Never (security critical) |
| `security` | Mixed | XSS vectors, unsafe APIs, sensitive storage. See `Security Rules` below for the rule_id breakdown | Each pattern is either an eval sink or origin-readable storage, so any script on the page can exfiltrate state | Never (security critical) |
| `architecture` | High | Layer violations (e.g., UI importing domain) | Once a UI file reaches into domain internals, the boundary stops constraining future change and refactors stall | Small projects, monoliths, or scripts |
| `eval` | High | eval(), new Function(), indirect eval | Whatever string lands there runs as code, so tainted input becomes arbitrary execution | Never (security critical) |
| `hardcodedSecrets` | High | API keys, tokens, passwords in source | The key is public the moment the repo is pushed; rotation is the only remediation | Never (security critical) |
| `cotLeakageMarker` | High | AI chain-of-thought leak markers (`<thinking>`, `<\|channel\|>`, `<\|start\|>assistant`, `to=functions.`) | Model internal state ships into production traces, UI, or documentation when these tags survive copy-paste | Projects that intentionally persist AI traces / transcripts |
| `openRedirect` | High | location.href/assign with user-controlled input | The attacker chooses the destination while the URL still wears your origin, the ideal phishing setup | Non-web projects |
| `rawHtml` | High | HTML concatenation with variables | String-concat HTML places attacker input directly into the live DOM, an XSS sink | Non-web projects |
| `sqliConcat` | High | SQL assembled via template interpolation or string concatenation | Interpolated SQL splices user input into the query body, the classic SQL injection | Projects without database access |
| `httpResource` | Medium | HTTP (non-HTTPS) resource URLs | Non-TLS resources let on-path attackers swap content (mixed-content downgrade, supply-chain tampering) | Development-only configs |
| `corsWildcard` | Medium | CORS wildcard origin (`cors({ origin: '*' })`, `Access-Control-Allow-Origin: *`). Scoped to `app/api/`, `pages/api/`, and `middleware.{ts,js}` | `*` lets any origin read the response, dropping the same-origin policy that protects user data | Rarely needed (scope already excludes UI/util files) |
| `transaction` | Medium | Multiple writes without transaction wrapper. Scoped to `usecases/`, `use-cases/`, `application/`, `services/`, `domain/`, `handlers/`, `app/`, `server/` directories and `app/**/route.{ts,js}` segments | A failure between writes leaves partial state behind: orphan rows, balance drift, inconsistent invariants | Non-database projects, or layout that does not use these directory names |
| `domAccess` | Medium | Direct DOM manipulation in React (.tsx/.jsx) | Imperative DOM mutations race the React reconciler; invariants break with no warning and bugs reproduce only intermittently | Non-React projects, or vanilla JS/TS |
| `syncIo` | Medium | readFileSync, writeFileSync (blocks event loop) | A single sync I/O call freezes the event loop, so every concurrent request stalls behind it | CLI tools, build scripts, or sync-only contexts |
| `bundleSize` | Medium | Full lodash/moment imports | A full `lodash` or `moment` import ships hundreds of KB to every visitor for a few utility functions | Backend/Node.js (no bundle size concerns) |
| `testAssertion` | Medium | Tests with no assertion, or only weak/mock/self-equal ones | An assertion that holds for any output (none, only toBeTruthy/toBeDefined, only toHaveBeenCalled, or expect(x).toBe(x)) lets green CI hide the regression | Playwright, custom test frameworks |
| `flakyTest` | Low | setTimeout, Math.random in tests | Time and RNG make failures non-deterministic, so people retry instead of investigating | Intentional timing/randomness tests |
| `generatedFile` | High | Warns on \*.generated.\*, \*.g.ts edits | Hand edits are overwritten on the next generation, so the fix disappears on the next run | No code generation in project |
| `testLocation` | Medium | Test files in src/ directory | Tests under `src/` reach the production bundle when build excludes do not catch them | Co-located test strategy (tests next to source) |
| `naming` | Mixed | Naming conventions (components, interfaces, types) | Inconsistent PascalCase naming for components, interfaces, and types defeats code search and the pattern recognition that picks them out | Different naming conventions in team/project |
| `noUseEffect` | Medium | Flags useEffect in .tsx/.jsx with alternative suggestions | `useEffect` for derivable state triggers extra renders and the dependency array becomes a stale-data trap | Projects using useEffect intentionally |
| `serviceWorker` | Medium | Service Worker registration with root scope (`{ scope: '/' }`). Suggests narrowing to a specific path | Root scope intercepts every navigation on the origin, so one misregistration hijacks the whole site | Projects intentionally serving the worker site-wide |
| `jwtClient` | Medium | Client-side JWT decode (`jwtDecode`, `jwt_decode`, `atob(token.split('.'))`). Suggests server-side `jwtVerify` | JWT payload is base64url. It is readable but also editable without a signature check, so trusting it on the client is an authorization bypass | Server-only JWT decode paths (e.g., Node-only files) |
| `astSecurity` | Mixed | AST-based: command/regex/require injection, stack exposure, path traversal, prototype pollution, bidi chars, env-var fallback, insecure RNG, unsafe HTML injection, client env leak, SSR secret bleed, postMessage origin (see below) | Aggregated AST checks. Each sub-rule has its own threat (see the sub-rule table below) | Non-Node.js projects |
| `invariant` | High | Blocks an edit that drifts a `.json` value away from the scalar pinned for it in `.invariants.json` (feature flags, i18n strings, design tokens) | A pinned value is a contract the rest of the app depends on; a silent edit that changes it ships a behavior change no human approved | Projects that do not pin invariant values |
<!-- END GENERATED: rules-table -->

### Security Rules (`security`)

The `security` toggle covers two rule_ids. Consumers filtering on the JSON `rule` field need the breakdown below.

<!-- BEGIN GENERATED: security-rules-table -->
| Sub-rule (rule_id) | Severity | Description | Why it matters |
| --- | --- | --- | --- |
| `security` | Mixed | `setTimeout('str')` / `setInterval('str')` / `postMessage(_, '*')` (High); sensitive `localStorage` / `sessionStorage` (Medium) | String timers behave like `eval`, wildcard `postMessage` broadcasts to any listener, and secrets in storage are reachable by any script on the origin |
| `dangerous-inner-html` | High | React `dangerouslySetInnerHTML={...}` (XSS sink, scoped to `.tsx` / `.jsx`) | Bypasses React's text escaping; a tainted variable lands as live DOM and runs the attacker's script |
<!-- END GENERATED: security-rules-table -->

### AST Security Rules (`astSecurity`)

Deep security checks using the [oxc](https://oxc.rs) parser. These analyze the AST directly, avoiding the false negatives of regex-based pattern matching.

<!-- BEGIN GENERATED: ast-security-rules-table -->
| Sub-rule | Severity | Description | Why it matters |
| --- | --- | --- | --- |
| `child-process-injection` | High | Non-literal args to exec/execSync/spawn/spawnSync. Scoped to `app/api/`, `pages/api/`, and files with `'use server'` directive | An untrusted segment becomes a shell command, so the request author runs arbitrary processes on the server |
| `err-stack-exposure` | High | Error stack traces leaked in HTTP responses (res.json/res.send). Scoped to `app/api/`, `pages/api/`, and `app/**/route.{ts,js}` segments | Stacks reveal file paths, library versions, and hosting layout, providing recon fuel for the next exploitation step |
| `non-literal-fs-path` | Medium | Non-literal file paths in fs.\* calls (path traversal risk). Scoped to `app/api/`, `pages/api/`, and files with `'use server'` directive | `..` segments slip past the intended root, exposing arbitrary files for read or overwrite |
| `non-literal-require` | Medium | Non-literal arg to require() (dynamic module loading). Scoped to `app/api/`, `pages/api/`, and files with `'use server'` directive | A tainted module name loads attacker-controlled JavaScript into the running process |
| `unsafe-regex` | Medium | Regex literals vulnerable to ReDoS (nested quantifiers, catastrophic backtracking) | A crafted input drives the engine into exponential backtracking. CPU hits 100% and the server stops serving others |
| `bidi-characters` | High | Unicode bidirectional control chars hidden in source (CVE-2021-42574 / Trojan Source) | Bidi chars reorder source at render time, so reviewers see different code than the compiler, and malicious logic hides in plain sight |
| `excessive-nesting` | High | Source nested past a safe depth — `()[]{}` brackets or `!`/`~` prefix runs | Deeply nested input overflows the parser's recursion and crashes the check process before any rule runs, which would silently let the edit through; a byte scan blocks it before the parse |
| `env-var-fallback` | High | `process.env.X \|\| 'default'` style — leaks secrets via hardcoded fallback | When the env var is unset, the hardcoded default ships as the real credential, and stays in source forever |
| `test-endpoint-prod-guard` | Medium | Test-named route file (`app/api/test-*/route.ts`, `pages/api/seed.ts`, …) with no `process.env.NODE_ENV === 'production'` guard in the file | A test-only endpoint shipped without a production guard exposes data seeding, deletion, or debug surfaces in production; this advisory prompts an in-file guard, or confirmation the route is excluded another way |
| `prototype-pollution` | High | `Object.assign({}, untrusted)`, `_.merge`, `Object.create` with `__proto__`/`constructor` | Writes to `__proto__` taint every object in the runtime. Auth checks misfire and, depending on the downstream sink, code execution opens |
| `math-random-insecure` | Mixed | `Math.random()` in token/ID/secret contexts. High when usage is concrete (`toString(36)` idiom or crypto-API argument); Medium when only inferable from naming heuristics (security-named var/fn, other `toString` radix). See [ADR-0003](docs/decisions/0003-math-random-severity-policy.md). | `Math.random` is predictable; tokens minted from it can be guessed and sessions hijacked |
| `unsafe-html-injection` | Mixed | Non-literal assignment to `innerHTML` (High) / `outerHTML` (Medium) / `document.write[ln]` (High). See [ADR-0008](docs/decisions/0008-unsafe-html-injection-rule-id-separation.md). | A tainted value reaches an HTML sink, and the parser runs whatever script tags it finds. XSS at the DOM layer |
| `client-env-public-leak` | High | `process.env.X` access inside a `'use client'` module (excluding `NEXT_PUBLIC_*` and the allow-list). Bundled to the browser by Next.js. | Next.js inlines `process.env.*` at build time; server-only secrets end up shipped inside the browser bundle |
| `ssr-secret-bleed` | High | Prevents server-only secrets from leaking to the browser via SSR returns. Flags secret-named properties (`apiKey`, `token`, …) or `process.env.*` secret values returned from `getServerSideProps` / `'use server'` Server Actions, since Next.js serializes those returns into the client payload. | The SSR return is serialized into the HTML payload. Every visitor receives the secret, including the ones who never authenticate |
| `postmessage-origin-missing` | High | `window.addEventListener('message', handler)` whose inline handler never reads `event.origin`. Without an origin check, the page accepts cross-origin postMessages from arbitrary senders. External handler references and param-side destructure are out of scope (1-file static analysis). | Any embedded iframe or popup can send a message and the handler trusts it, so the page runs commands chosen by an attacker |
<!-- END GENERATED: ast-security-rules-table -->

## Subcommands

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

Calling `guardrails` with no subcommand enters **hook mode** (reads tool input JSON from stdin). `guardrails --help` shows the full description including exit codes.

## Exit Codes

Claude Code reads the exit code to decide whether to pass, surface a warning to the AI, or halt the tool call. Per the PreToolUse contract only exit `2` halts the call; `0` allows and `1` / `64` are non-blocking (stderr is surfaced to the AI, the tool proceeds). A panic mid-check also exits `2` so an incomplete check fails closed rather than letting the edit through.

### Hook mode (no subcommand)

| Code | Meaning                                                                                                                                            |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Pass — no violations                                                                                                                               |
| 1    | Warning only — non-blocking severity violations, tool proceeds, stderr shown to AI                                                                 |
| 2    | Blocked — violations at or above `severity.blockThreshold` (default: `high`), oversized stdin, or a panic mid-check (all fail-closed), tool halted |
| 64   | Hook input error — malformed JSON, stdin read failure, or clap usage failure (non-blocking)                                                        |

### Subcommands (`prefetch`)

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| 0    | Success                                       |
| 64   | Usage error (clap parse failure)              |
| 65   | Data error (unsupported platform)             |
| 74   | I/O error (network / extract / cache failure) |

> **BREAKING (v0.16+)**: Non-blocking severity violations (below `severity.blockThreshold`) now exit `1` (was `0`). Hook stdin / JSON / oversized input failures now exit `64` (was `1` or `2`). Internal panics now exit `70`. The JSON `decision` field (`allow` / `block`) is unchanged — it still tracks blocking violations only.

> **BREAKING (v0.21+)**: Oversized stdin (over the 10 MB cap) now exits `2` (block), not `64`. Exit `64` does not block a PreToolUse call, so the prior `64` let oversized payloads pass through; `2` makes the resource-boundary guard fail-closed. Malformed JSON and stdin read failures stay at `64` (non-blocking, fail-open by design).

> **BREAKING (v0.21+)**: A panic during a hook-mode check now exits `2` (block), not `70`. Exit `70` does not block a PreToolUse call, so a panic mid-check used to let the unchecked edit through; `2` makes it fail-closed. Exit `70` remains for internal panics in the `prefetch` and hidden AST-child subcommands.

> **BREAKING (v0.17+)**: `severity.blockOn` (an array) is replaced by `severity.blockThreshold` (a single severity). Violations at or above the threshold block; below it warn. The default `"high"` matches the old `["critical", "high"]`. Unknown `blockOn` keys are silently ignored, so a config that listed `medium` or `low` must switch to `"blockThreshold": "medium"` / `"low"`; the rare `blockOn: []` (block nothing) has no replacement.

## JSON Output Mode

Pass `--json` to emit a structured JSON report on stdout. Human-readable output stays on stderr; exit codes are unchanged. Designed for agents (e.g., Claude Code) that need a stable, parseable contract.

```sh
guardrails --json < tool-call.json
```

> **BREAKING (v0.15+)**: the `GUARDRAILS_JSON=1` env from v0.14 is removed. Use `--json` instead. To keep JSON output on every hook call, add the flag to your hook command (see [As Claude Code Hook](#as-claude-code-hook)).

> **BREAKING (v0.15+)**: success output is wrapped in a `SuccessEnvelope` (`{ data, degraded, notes }`) per [ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md). The pre-envelope shape (`{ violations, decision, exit_code }`) is gone — the process exit code remains the source of truth for hook decisions.

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

| Field             | Type                                           | Notes                                                                                                                                                                                                                                       |
| ----------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data.violations` | array                                          | Both blocking and warning entries; distinguish via `severity`                                                                                                                                                                               |
| `data.decision`   | `"block"` / `"allow"`                          | `block` only when an entry is at or above `severity.blockThreshold`                                                                                                                                                                         |
| `severity`        | `"critical"` / `"high"` / `"medium"` / `"low"` | Lowercase                                                                                                                                                                                                                                   |
| `line`            | integer or `null`                              | `null` when location is unknown                                                                                                                                                                                                             |
| `origin`          | `"preexisting"` (optional)                     | Present only on violations demoted because they existed before the edit, and only when `diffAware` is on. Every other entry omits the field: the tool does not before-compare it, so it makes no origin claim (see [diffAware](#diffaware)) |
| `degraded`        | boolean                                        | `true` when any note is present. Union of environmental notes (project root canonicalize failure, config load failure, oxlint unavailable) and post-edit content fallback notes. Always read `notes` for the cause                          |
| `notes`           | array of strings                               | Reasons for degradation in order of source (project root → config → linter → content fallback). Not deduplicated. Non-empty implies `degraded: true`                                                                                        |

### Error envelope

When `--json` is set and stdin is invalid, guardrails emits an `ErrorEnvelope` on stdout. Malformed JSON and IO failures exit `64` (hook input error, non-blocking). An oversized payload (over the 10 MB cap) exits `2` (block, fail-closed) since v0.21 — see [Exit Codes](#exit-codes).

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

| Field              | Type                                            | Notes                                                                                           |
| ------------------ | ----------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `error.code`       | `"USAGE_ERROR"` / `"DATA_ERROR"` / `"IO_ERROR"` | SCREAMING_SNAKE_CASE per [ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md) |
| `error.message`    | string                                          | Human-readable detail (also printed on stderr)                                                  |
| `error.next_step`  | string (optional)                               | Concrete action to recover                                                                      |
| `error.candidates` | array of strings (optional)                     | Recovery candidates (omitted when empty)                                                        |
| `error.retryable`  | boolean                                         | `true` only when the cause is a transient failure                                               |

> **Case mixing**: `severity` is lowercase (legacy from v0.14) and `error.code` is SCREAMING_SNAKE_CASE ([ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md)). The mix is intentional — both shapes are stable.

Without `--json`, output is byte-for-byte identical to the human-readable default mode.

## Configuration

Place a `.guardrails.json` at your project root. The format is the flat `ProjectConfig` schema (no `guardrails` key wrapper). All fields are optional — only specify what you want to override. This is the agent-neutral path that works the same from Claude Code, codex CLI, or any other AI agent that runs guardrails as a hook.

> **Other supported paths**:
>
> - `.claude/tools.json` (`guardrails` key configured) — Claude Code's 4-tool pipeline convention. Used when `.guardrails.json` is absent.
> - `.claude-guardrails.json` — legacy fallback. Used when neither of the above is found.
>
> If multiple files exist, the priority is `.guardrails.json` > `.claude/tools.json` > `.claude-guardrails.json`. Only the first one found is loaded.

**Defaults** (no config file needed):

- All rules enabled
- Blocks on `critical` and `high` severity

### Schema

`.guardrails.json` (recommended, agent-neutral):

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
    "invariant": true
  },
  "oxlint": {
    "deny": [],
    "allow": []
  },
  "severity": {
    "blockThreshold": "high"
  }
}
```

For `.claude/tools.json`, wrap the same object under a `"guardrails"` key (4-tool pipeline convention).

#### `oxlint.deny` / `oxlint.allow`

Add extra rules to enforce or suppress the default deny list:

```json
{
  "oxlint": {
    "deny": ["eslint/curly"],
    "allow": ["eslint/no-console"]
  }
}
```

- `deny`: additional rules to enable via `--deny` (merged with defaults)
- `allow`: rules to exclude from the deny list (e.g., allow `console.log` for CLI projects)

#### `diffAware`

Off by default. When enabled, an edit to a file that already contains blocking violations blocks only the violations the edit introduces; violations that existed before the edit demote to warnings (exit 1), so the edit is not gated on legacy issues it did not create.

```json
{
  "diffAware": true
}
```

- Demotion is limited to rules whose violations are fully determined by a single reported line (currently `eval`). Violations of every other rule, and all oxlint-delegated violations, keep blocking even when they pre-existed.
- Matching counts (rule, trimmed line text) pairs, so pasting an extra copy of an existing violating line still blocks the surplus copy.
- Fail-safe: when the before-edit state cannot be trusted (unreadable file, degraded edit resolution, before-edit parse failure), demotion is skipped entirely, every violation keeps blocking, and a `demotion skipped (...)` note names the cause. Writing a brand-new file is not a failure: it has no before content, so nothing demotes and every violation blocks, with no note.
- With the toggle on, each demoted violation in the JSON output carries `"origin": "preexisting"`, and demoted warnings are marked `(preexisting)` on stderr. Every other entry omits `origin`: the tool only before-compares the demoted ones, so it claims nothing about the rest. With the toggle off, the `origin` field is absent and output is byte-identical to previous versions.

### Examples

**Default** (no config needed):

All rules enabled, oxlint auto-provisioned, AI-tuned deny rules active.

**Custom rules only** (disable oxlint):

```json
{
  "rules": {
    "oxlint": false
  }
}
```

**Backend (Node.js/API)** — disable frontend-specific rules, allow console:

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

**Block all severities** (`low` is the floor, so the threshold blocks everything):

```json
{
  "severity": {
    "blockThreshold": "low"
  }
}
```

**Disable guardrails for a project**:

```json
{
  "enabled": false
}
```

### Config Resolution

The config file is found by walking up from the target file to the nearest `.git` directory. Discovery stops at the first file found in this order:

```text
project-root/
├── .guardrails.json         ← preferred (agent-neutral, flat schema)
├── .claude/
│   └── tools.json           ← Claude Code 4-tool pipeline (guardrails key)
├── .git/
├── src/
│   └── app.ts               ← file being checked → walks up to find config
└── .claude-guardrails.json  ← legacy fallback
```

## Using with Existing Linters

If you already run oxlint via lefthook, husky, or lint-staged on commit, guardrails' linter checks may overlap. The two serve different purposes:

| Tool              | When                | Purpose                               |
| ----------------- | ------------------- | ------------------------------------- |
| guardrails (hook) | On every file write | Prevent issues before they're written |
| lefthook / husky  | On commit           | Final gate before code enters history |

To disable oxlint in guardrails and rely on your commit hook instead:

```json
{
  "rules": {
    "oxlint": false
  }
}
```

This keeps guardrails' custom security rules (sensitiveFile, cryptoWeak, etc.) active while avoiding duplicate linter checks.

## Known Limitations

### Line-based rules (architecture, security, cryptoWeak, etc.)

These rules use `non_comment_lines()` which tracks `/* ... */` block comment state across lines and filters `//` line comments:

- **String literals containing `/*` or `*/`**: Comment markers inside string literals (e.g., `let s = "/* not a comment */";`) are treated as real comment boundaries, which may cause incorrect line filtering in rare cases.
- **Asterisk at line start**: Lines starting with `*` are treated as JSDoc continuations.

### Scanner-based rules (sensitiveLogging, testAssertion)

These rules use `StringScanner` which tracks comment state across lines:

- **JavaScript regex literals**: Patterns containing `//` or `/*` (e.g., `/https:\/\//`) may be misidentified as comment starts.

These trade-offs are acceptable for guardrails use cases where false positives are preferable to false negatives.

### File extension scope

JS analysis (oxlint, AST, ast-security) covers `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, and `.mts`. CommonJS `.cjs`/`.cts` are out of scope: they are predominantly Node tooling (build config, CLI, generators) rather than frontend code.

## Companion Tools

This tool is part of a 4-tool quality pipeline for Claude Code. Each covers a
different phase — install the full suite for comprehensive coverage:

```bash
brew install thkt/tap/guardrails thkt/tap/formatter thkt/tap/reviews thkt/tap/gates
```

| Tool                                           | Hook        | Timing            | Role                              |
| ---------------------------------------------- | ----------- | ----------------- | --------------------------------- |
| **guardrails**                                 | PreToolUse  | Before Write/Edit | Lint + security checks            |
| [formatter](https://github.com/thkt/formatter) | PostToolUse | After Write/Edit  | Auto code formatting              |
| [reviews](https://github.com/thkt/reviews)     | PreToolUse  | Before Skill      | Static analysis context injection |
| [gates](https://github.com/thkt/gates)         | Stop        | Agent completion  | Quality gates (knip, tsgo, madge) |

See [thkt/tap](https://github.com/thkt/homebrew-tap) for setup details.

## License

MIT
