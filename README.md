# claude-guardrails

Code quality checker for Claude Code's PreToolCall hook. Combines biome CLI with custom rules to validate code and provide actionable fix suggestions.

## Features

- **biome integration**: 300+ lint rules from [biomejs.dev](https://biomejs.dev)
- **Custom rules**: Security patterns biome doesn't cover
- **Claude-optimized output**: Actionable fix suggestions in stderr

## Installation

### Homebrew (Recommended)

```bash
brew install thkt/tap/guardrails
```

### From Release

Download the latest binary from [Releases](https://github.com/thkt/claude-guardrails/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/claude-guardrails/releases/latest/download/guardrails-aarch64-apple-darwin -o guardrails
chmod +x guardrails
mv guardrails ~/.local/bin/
```

### From Source

```bash
git clone https://github.com/thkt/claude-guardrails.git
cd claude-guardrails
cargo build --release
cp target/release/guardrails ~/.local/bin/
```

## Usage

### As Claude Code Hook

Add to `~/.claude/settings.json`:

```json
{
  "hooks" : [
    {
      "command" : "guardrails",
      "timeout" : 1000,
      "type" : "command"
    }
  ],
  "matcher" : "Write|Edit|MultiEdit"
}
```

## Requirements

- [biome](https://biomejs.dev) CLI installed (`brew install biome` or `npm i -g @biomejs/biome`)
- Project's `biome.json` is automatically used if present

## Custom Rules

See `src/rules/` for custom rules that complement biome's built-in checks:

| Rule               | Severity | Description                                     | When to disable                                  |
| ------------------ | -------- | ----------------------------------------------- | ------------------------------------------------ |
| `sensitiveFile`    | Critical | Blocks writes to .env, credentials.\*, \*.pem   | Never (security critical)                        |
| `cryptoWeak`       | High     | Detects MD5, SHA1, DES, RC4 usage               | Legacy system maintenance with known constraints |
| `sensitiveLogging` | High     | Detects password/token/secret in console.log    | Never (security critical)                        |
| `security`         | High     | XSS vectors, unsafe APIs                        | Never (security critical)                        |
| `architecture`     | High     | Layer violations (e.g., UI importing domain)    | Small projects, monoliths, or scripts            |
| `transaction`      | Medium   | Multiple writes without transaction wrapper     | Non-database projects                            |
| `domAccess`        | Medium   | Direct DOM manipulation in React (.tsx/.jsx)    | Non-React projects, or vanilla JS/TS             |
| `syncIo`           | Medium   | readFileSync, writeFileSync (blocks event loop) | CLI tools, build scripts, or sync-only contexts  |
| `bundleSize`       | Medium   | Full lodash/moment imports                      | Backend/Node.js (no bundle size concerns)        |
| `testAssertion`    | Medium   | Tests without expect() or assert calls          | Playwright, custom test frameworks               |
| `flakyTest`        | Low      | setTimeout, Math.random in tests                | Intentional timing/randomness tests              |
| `generatedFile`    | High     | Warns on \*.generated.\*, \*.g.ts edits         | No code generation in project                    |
| `testLocation`     | Medium   | Test files in src/ directory                    | Co-located test strategy (tests next to source)  |
| `naming`           | Mixed    | Naming conventions (hooks, components, types)   | Different naming conventions in team/project     |

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | All checks passed                |
| 2    | Issues found (operation blocked) |

## Configuration

Create `~/.config/guardrails/config.json` to customize rules:

```bash
mkdir -p ~/.config/guardrails
```

```json
{
  "enabled": true,
  "rules": {
    "biome": true,
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": true,
    "transaction": true,
    "domAccess": true,
    "syncIo": true,
    "bundleSize": true,
    "testAssertion": true,
    "flakyTest": true,
    "generatedFile": true,
    "testLocation": true,
    "naming": true
  },
  "severity": {
    "blockOn": ["critical", "high"]
  }
}
```

### Examples

**biome only** (disable custom rules):

```json
{
  "rules": {
    "biome": true,
    "sensitiveFile": false,
    "cryptoWeak": false,
    "sensitiveLogging": false,
    "security": false,
    "architecture": false,
    "transaction": false,
    "domAccess": false,
    "syncIo": false,
    "bundleSize": false,
    "testAssertion": false,
    "flakyTest": false,
    "generatedFile": false,
    "testLocation": false,
    "naming": false
  }
}
```

**Custom rules only** (disable biome):

```json
{
  "rules": {
    "biome": false
  }
}
```

**Security-focused** (high severity rules only):

```json
{
  "rules": {
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": false,
    "transaction": false,
    "domAccess": false,
    "syncIo": false,
    "bundleSize": false,
    "testAssertion": false,
    "flakyTest": false,
    "generatedFile": false,
    "testLocation": false,
    "naming": false
  }
}
```

### Project Type Presets

**Frontend (React/Vue/Angular)**:

```json
{
  "rules": {
    "biome": true,
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": true,
    "domAccess": true,
    "bundleSize": true,
    "naming": true,
    "syncIo": false,
    "transaction": false
  }
}
```

**Backend (Node.js/API)**:

```json
{
  "rules": {
    "biome": true,
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": true,
    "transaction": true,
    "syncIo": true,
    "domAccess": false,
    "bundleSize": false,
    "naming": false
  }
}
```

**CLI/Scripts**:

```json
{
  "rules": {
    "biome": true,
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": false,
    "transaction": false,
    "domAccess": false,
    "syncIo": false,
    "bundleSize": false
  }
}
```

### Config file search order

1. Next to the binary (and parent directories)
2. `./config.json` (current directory)
3. `$XDG_CONFIG_HOME/guardrails/config.json` or `~/.config/guardrails/config.json`

## Known Limitations

### Line-based rules (architecture, security, cryptoWeak, etc.)

These rules use `starts_with_comment` helper which only checks line beginnings:

- **Multi-line block comments**: Lines inside block comments may not be recognized as comments.
- **Mid-line block comment endings**: Code after `*/` on the same line may be missed.
- **Asterisk at line start**: Lines starting with `* ` are treated as JSDoc continuations.

### Scanner-based rules (sensitiveLogging, testAssertion)

These rules use `StringScanner` which tracks comment state across lines:

- **JavaScript regex literals**: Patterns containing `//` or `/*` (e.g., `/https:\/\//`) may be misidentified as comment starts.

These trade-offs are acceptable for guardrails use cases where false positives are preferable to false negatives.

## License

MIT
