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

| Outcome                                              | Exit |
| ---------------------------------------------------- | ---- |
| Already cached or downloaded successfully            | 0    |
| Download failed (network or unsupported platform)    | 1    |

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
| `sensitiveFile`    | Critical | Blocks writes to .env, credentials.\*, \*.pem                            | Never (security critical)                        |
| `cryptoWeak`       | High     | Detects MD5, SHA1, DES, RC4 usage                                        | Legacy system maintenance with known constraints |
| `sensitiveLogging` | High     | Detects password/token/secret in console.log                             | Never (security critical)                        |
| `security`         | High     | XSS vectors, unsafe APIs, postMessage                                    | Never (security critical)                        |
| `architecture`     | High     | Layer violations (e.g., UI importing domain)                             | Small projects, monoliths, or scripts            |
| `eval`             | High     | eval(), new Function(), indirect eval                                    | Never (security critical)                        |
| `hardcodedSecrets` | High     | API keys, tokens, passwords in source                                    | Never (security critical)                        |
| `openRedirect`     | High     | location.href/assign with user-controlled input                          | Non-web projects                                 |
| `rawHtml`          | High     | HTML concatenation with variables                                        | Non-web projects                                 |
| `httpResource`     | Medium   | HTTP (non-HTTPS) resource URLs                                           | Development-only configs                         |
| `transaction`      | Medium   | Multiple writes without transaction wrapper                              | Non-database projects                            |
| `domAccess`        | Medium   | Direct DOM manipulation in React (.tsx/.jsx)                             | Non-React projects, or vanilla JS/TS             |
| `syncIo`           | Medium   | readFileSync, writeFileSync (blocks event loop)                          | CLI tools, build scripts, or sync-only contexts  |
| `bundleSize`       | Medium   | Full lodash/moment imports                                               | Backend/Node.js (no bundle size concerns)        |
| `testAssertion`    | Medium   | Tests without expect() or assert calls                                   | Playwright, custom test frameworks               |
| `flakyTest`        | Low      | setTimeout, Math.random in tests                                         | Intentional timing/randomness tests              |
| `generatedFile`    | High     | Warns on \*.generated.\*, \*.g.ts edits                                  | No code generation in project                    |
| `testLocation`     | Medium   | Test files in src/ directory                                             | Co-located test strategy (tests next to source)  |
| `naming`           | Mixed    | Naming conventions (hooks, components, types)                            | Different naming conventions in team/project     |
| `noUseEffect`      | Medium   | Flags useEffect in .tsx/.jsx with alternative suggestions                | Projects using useEffect intentionally           |
| `astSecurity`      | Mixed    | AST-based: command injection, stack exposure, path traversal (see below) | Non-Node.js projects                             |

### AST Security Rules (`astSecurity`)

Deep security checks using the [oxc](https://oxc.rs) parser. These analyze the AST directly, avoiding the false negatives of regex-based pattern matching.

| Sub-rule                  | Severity | Description                                                     |
| ------------------------- | -------- | --------------------------------------------------------------- |
| `child-process-injection` | High     | Non-literal args to exec/execSync/spawn/spawnSync               |
| `err-stack-exposure`      | High     | Error stack traces leaked in HTTP responses (res.json/res.send) |
| `non-literal-fs-path`     | Medium   | Non-literal file paths in fs.\* calls (path traversal risk)     |

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | All checks passed                |
| 2    | Issues found (operation blocked) |

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
