**English** | [日本語](README.ja.md)

# guardrails

Code quality checker for Claude Code's PreToolCall hook. Combines external linters with custom rules to validate code and provide actionable fix suggestions.

## Features

- **oxlint auto-provision**: Automatically resolves or downloads [oxlint](https://oxc.rs) — no manual install needed
- **AI-tuned deny rules**: Enables `no-explicit-any`, `ban-ts-comment`, `no-non-null-assertion`, `no-console` by default via `--deny`
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

| Outcome                                              | Exit | `error.code`     |
| ---------------------------------------------------- | ---- | ---------------- |
| Already cached or downloaded successfully            | 0    | (none)           |
| Unsupported platform (e.g. Windows / non-amd64)      | 65   | `DATA_ERROR`     |
| Network failure (download / read error)              | 74   | `IO_ERROR`       |
| Extract failure (tar / cache write / rename)         | 74   | `IO_ERROR`       |
| Cache directory unavailable (no `XDG_CACHE_HOME` / `HOME`) | 74   | `IO_ERROR`       |

> **BREAKING (v0.15+)**: `prefetch` exit codes changed from `0` / `1` to sysexits.h values (`0` / `65` / `74`). Pass `--json` to receive a structured `ErrorEnvelope` (`{ error: { code, message, next_step, retryable } }`) on failure.

### AI-Tuned Deny Rules

guardrails enables these oxlint rules via `--deny` (off by default in oxlint, important for AI-generated code):

| Rule                               | Why                                      |
| ---------------------------------- | ---------------------------------------- |
| `typescript/no-explicit-any`       | AI uses `any` / `as any` to bypass types |
| `typescript/ban-ts-comment`        | AI uses `@ts-ignore` to suppress errors  |
| `typescript/no-non-null-assertion` | AI uses `!` to skip null checks          |
| `eslint/no-console`                | AI leaves debug `console.log`            |

Customize via `oxlint.deny` / `oxlint.allow` in config (see below).

## Custom Rules

See `src/rules/` for custom rules that complement external linters.

### Rules

| Rule               | Severity | Description                                                              | When to disable                                  |
| ------------------ | -------- | ------------------------------------------------------------------------ | ------------------------------------------------ |
| `sensitiveFile`         | Critical | Blocks writes to .env, credentials.\*, \*.pem                            | Never (security critical)                              |
| `cryptoWeak`            | High     | Detects MD5, SHA1, DES, RC4 usage                                        | Legacy system maintenance with known constraints       |
| `sensitiveLogging`      | High     | Detects password/token/secret in console.log                             | Never (security critical)                              |
| `security`              | Mixed    | XSS vectors, unsafe APIs, sensitive storage. See `Security Rules` below for the rule_id breakdown | Never (security critical)                              |
| `architecture`          | High     | Layer violations (e.g., UI importing domain)                             | Small projects, monoliths, or scripts                  |
| `eval`                  | High     | eval(), new Function(), indirect eval                                    | Never (security critical)                              |
| `hardcodedSecrets`      | High     | API keys, tokens, passwords in source                                    | Never (security critical)                              |
| `cotLeakageMarker`      | High     | AI chain-of-thought leak markers (`<thinking>`, `<\|channel\|>`, `<\|start\|>assistant`, `to=functions.`) | Projects that intentionally persist AI traces / transcripts |
| `openRedirect`          | High     | location.href/assign with user-controlled input                          | Non-web projects                                       |
| `rawHtml`               | High     | HTML concatenation with variables                                        | Non-web projects                                       |
| `sqliConcat`            | High     | SQL assembled via template interpolation or string concatenation         | Projects without database access                       |
| `httpResource`          | Medium   | HTTP (non-HTTPS) resource URLs                                           | Development-only configs                               |
| `corsWildcard`          | Medium   | CORS wildcard origin (`cors({ origin: '*' })`, `Access-Control-Allow-Origin: *`). Scoped to `app/api/`, `pages/api/`, and `middleware.{ts,js}` | Rarely needed (scope already excludes UI/util files) |
| `transaction`           | Medium   | Multiple writes without transaction wrapper. Scoped to `usecases/`, `services/`, `domain/`, `handlers/`, `app/`, `server/` directories and `app/**/route.{ts,js}` segments | Non-database projects, or layout that does not use these directory names |
| `domAccess`             | Medium   | Direct DOM manipulation in React (.tsx/.jsx)                             | Non-React projects, or vanilla JS/TS                   |
| `syncIo`                | Medium   | readFileSync, writeFileSync (blocks event loop)                          | CLI tools, build scripts, or sync-only contexts        |
| `bundleSize`            | Medium   | Full lodash/moment imports                                               | Backend/Node.js (no bundle size concerns)              |
| `testAssertion`         | Medium   | Tests without expect() or assert calls                                   | Playwright, custom test frameworks                     |
| `flakyTest`             | Low      | setTimeout, Math.random in tests                                         | Intentional timing/randomness tests                    |
| `generatedFile`         | High     | Warns on \*.generated.\*, \*.g.ts edits                                  | No code generation in project                          |
| `testLocation`          | Medium   | Test files in src/ directory                                             | Co-located test strategy (tests next to source)        |
| `naming`                | Mixed    | Naming conventions (hooks, components, types)                            | Different naming conventions in team/project           |
| `noUseEffect`           | Medium   | Flags useEffect in .tsx/.jsx with alternative suggestions                | Projects using useEffect intentionally                 |
| `astSecurity`           | Mixed    | AST-based: command/regex/require injection, stack exposure, path traversal, prototype pollution, bidi chars, env-var fallback, insecure RNG, unsafe HTML injection (see below) | Non-Node.js projects                                   |

### Security Rules (`security`)

The `security` toggle covers two rule_ids. Consumers filtering on the JSON `rule` field need the breakdown below.

| Sub-rule (rule_id)     | Severity | Description                                                                                                          |
| ---------------------- | -------- | -------------------------------------------------------------------------------------------------------------------- |
| `security`             | Mixed    | `setTimeout('str')` / `setInterval('str')` / `postMessage(_, '*')` (High); sensitive `localStorage` / `sessionStorage` (Medium) |
| `dangerous-inner-html` | High     | React `dangerouslySetInnerHTML={...}` (XSS sink, scoped to `.tsx` / `.jsx`)                                          |

### AST Security Rules (`astSecurity`)

Deep security checks using the [oxc](https://oxc.rs) parser. These analyze the AST directly, avoiding the false negatives of regex-based pattern matching.

| Sub-rule                  | Severity | Description                                                                                                                                |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `child-process-injection` | High     | Non-literal args to exec/execSync/spawn/spawnSync. Scoped to `app/api/`, `pages/api/`, and files with `'use server'` directive             |
| `err-stack-exposure`      | High     | Error stack traces leaked in HTTP responses (res.json/res.send). Scoped to `app/api/`, `pages/api/`, and `app/**/route.{ts,js}` segments   |
| `non-literal-fs-path`     | Medium   | Non-literal file paths in fs.\* calls (path traversal risk). Scoped to `app/api/`, `pages/api/`, and files with `'use server'` directive   |
| `non-literal-require`     | Medium   | Non-literal arg to require() (dynamic module loading). Scoped to `app/api/`, `pages/api/`, and files with `'use server'` directive         |
| `unsafe-regex`            | Medium   | Regex literals vulnerable to ReDoS (nested quantifiers, catastrophic backtracking)                                                         |
| `bidi-characters`         | High     | Unicode bidirectional control chars hidden in source (CVE-2021-42574 / Trojan Source)                                                      |
| `env-var-fallback`        | High     | `process.env.X \|\| 'default'` style — leaks secrets via hardcoded fallback                                                                |
| `prototype-pollution`     | High     | `Object.assign({}, untrusted)`, `_.merge`, `Object.create` with `__proto__`/`constructor`                                                  |
| `math-random-insecure`    | Mixed    | `Math.random()` in token/ID/secret contexts. High when usage is concrete (`toString(36)` idiom or crypto-API argument); Medium when only inferable from naming heuristics (security-named var/fn, other `toString` radix). See [ADR-0003](docs/decisions/0003-math-random-severity-policy.md). |
| `unsafe-html-injection`   | Mixed    | Non-literal assignment to `innerHTML` (High) / `outerHTML` (Medium) / `document.write[ln]` (High). See [ADR-0008](docs/decisions/0008-unsafe-html-injection-rule-id-separation.md). |
| `ssr-secret-bleed`        | High     | Prevents server-only secrets from leaking to the browser via SSR returns. Flags secret-named properties (`apiKey`, `token`, …) or `process.env.*` secret values returned from `getServerSideProps` / `'use server'` Server Actions, since Next.js serializes those returns into the client payload. |

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

Claude Code reads the exit code to decide whether to pass, surface a warning to the AI, or halt the tool call.

### Hook mode (no subcommand)

| Code | Meaning                                                                       |
| ---- | ----------------------------------------------------------------------------- |
| 0    | Pass — no violations                                                                          |
| 1    | Warning only — non-blocking severity violations, tool proceeds, stderr shown to AI            |
| 2    | Blocked — violations matching `severity.blockOn` (default: `critical`, `high`), tool halted   |
| 64   | Hook input error — malformed JSON, oversized payload, or clap usage failure                   |
| 70   | Internal error — panic or invariant violation (fail-closed)                                   |

### Subcommands (`prefetch`)

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| 0    | Success                                                              |
| 64   | Usage error (clap parse failure)                                     |
| 65   | Data error (unsupported platform)                                    |
| 74   | I/O error (network / extract / cache failure)                        |

> **BREAKING (v0.16+)**: Non-blocking severity violations (not matching `severity.blockOn`) now exit `1` (was `0`). Hook stdin / JSON / oversized input failures now exit `64` (was `1` or `2`). Internal panics now exit `70`. The JSON `decision` field (`allow` / `block`) is unchanged — it still tracks blocking violations only.

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

| Field             | Type                                            | Notes                                                            |
| ----------------- | ----------------------------------------------- | ---------------------------------------------------------------- |
| `data.violations` | array                                           | Both blocking and warning entries; distinguish via `severity`    |
| `data.decision`   | `"block"` / `"allow"`                           | `block` only when at least one entry matches `severity.blockOn`  |
| `severity`        | `"critical"` / `"high"` / `"medium"` / `"low"`  | Lowercase                                                        |
| `line`            | integer or `null`                               | `null` when location is unknown                                  |
| `degraded`        | boolean                                         | `true` when a tool was unavailable (e.g. oxlint not installed)   |
| `notes`           | array of strings                                | Reasons for degradation; non-empty implies `degraded: true`      |

### Error envelope

When `--json` is set and stdin is invalid (malformed JSON, oversized payload, IO failure), guardrails emits an `ErrorEnvelope` on stdout and exits `64` (hook input error).

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

| Field             | Type                                            | Notes                                                            |
| ----------------- | ----------------------------------------------- | ---------------------------------------------------------------- |
| `error.code`      | `"USAGE_ERROR"` / `"DATA_ERROR"` / `"IO_ERROR"` | SCREAMING_SNAKE_CASE per [ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md) |
| `error.message`   | string                                          | Human-readable detail (also printed on stderr)                   |
| `error.next_step` | string (optional)                               | Concrete action to recover                                       |
| `error.candidates`| array of strings (optional)                     | Recovery candidates (omitted when empty)                         |
| `error.retryable` | boolean                                         | `true` only when the cause is a transient failure                |

> **Case mixing**: `severity` is lowercase (legacy from v0.14) and `error.code` is SCREAMING_SNAKE_CASE ([ADR-0005](docs/decisions/0005-json-envelope-and-sysexits-adoption.md)). The mix is intentional — both shapes are stable.

Without `--json`, output is byte-for-byte identical to the human-readable default mode.

## Configuration

Add a `guardrails` key to `.claude/tools.json` at your project root. All fields are optional — only specify what you want to override.

> **Migration**: `.claude-guardrails.json` at the project root is still supported as a legacy fallback. If both exist, `.claude/tools.json` takes priority.

**Defaults** (no config file needed):

- All rules enabled
- Blocks on `critical` and `high` severity

### Schema

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

Add extra rules to enforce or suppress the default deny list:

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

- `deny`: additional rules to enable via `--deny` (merged with defaults)
- `allow`: rules to exclude from the deny list (e.g., allow `console.log` for CLI projects)

### Examples

**Default** (no config needed):

All rules enabled, oxlint auto-provisioned, AI-tuned deny rules active.

**Custom rules only** (disable oxlint):

```json
{
  "guardrails": {
    "rules": {
      "oxlint": false
    }
  }
}
```

**Backend (Node.js/API)** — disable frontend-specific rules, allow console:

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

**Block all severities**:

```json
{
  "guardrails": {
    "severity": {
      "blockOn": ["critical", "high", "medium", "low"]
    }
  }
}
```

**Disable guardrails for a project**:

```json
{
  "guardrails": {
    "enabled": false
  }
}
```

### Config Resolution

The config file is found by walking up from the target file to the nearest `.git` directory.

```text
project-root/
├── .claude/
│   └── tools.json     ← preferred (guardrails key)
├── .git/
├── src/
│   └── app.ts         ← file being checked → walks up to find config
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
  "guardrails": {
    "rules": {
      "oxlint": false
    }
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
