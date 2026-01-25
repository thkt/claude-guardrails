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
  "hooks": {
    "preToolCall": [
      {
        "matcher": "Write",
        "command": "guardrails"
      }
    ]
  }
}
```

## Requirements

- [biome](https://biomejs.dev) CLI installed (`brew install biome` or `npm i -g @biomejs/biome`)
- Project's `biome.json` is automatically used if present

## Custom Rules

See `src/rules/` for custom rules that complement biome's built-in checks:

| Rule               | Severity | Description                                                   |
| ------------------ | -------- | ------------------------------------------------------------- |
| `sensitiveFile`    | Critical | Blocks writes to .env, credentials._, _.pem, id_rsa           |
| `cryptoWeak`       | High     | Detects MD5, SHA1, DES, RC4 usage                             |
| `sensitiveLogging` | High     | Detects password/token/secret in console.log                  |
| `security`         | High     | XSS vectors, unsafe APIs                                      |
| `architecture`     | High     | Layer violations (e.g., UI importing domain)                  |
| `transaction`      | Medium   | Multiple writes without transaction wrapper                   |
| `domAccess`        | Medium   | Direct DOM manipulation in React (.tsx/.jsx)                  |
| `syncIo`           | Medium   | readFileSync, writeFileSync (blocks event loop)               |
| `bundleSize`       | Medium   | Full lodash/moment imports                                    |
| `testAssertion`    | Medium   | Tests without expect() or assert calls                        |
| `flakyTest`        | Low      | setTimeout, Math.random in tests                              |
| `generatedFile`    | High     | Warns on _.generated._, \*.g.ts edits                         |
| `testLocation`     | Medium   | Test files in src/ directory                                  |
| `naming`           | Mixed    | Naming conventions (hooks=High, components=Medium, types=Low) |

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

### Config file search order

1. Next to the binary (and parent directories)
2. `./config.json` (current directory)
3. `$XDG_CONFIG_HOME/guardrails/config.json` or `~/.config/guardrails/config.json`

## License

MIT
