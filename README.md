# claude-guardrails

Code quality checker for Claude Code's PreToolCall hook. Combines biome CLI with custom rules to validate code and provide actionable fix suggestions.

## Features

- **biome integration**: 300+ lint rules from [biomejs.dev](https://biomejs.dev)
- **Custom rules**: Security patterns biome doesn't cover
- **Claude-optimized output**: Actionable fix suggestions in stderr

## Installation

### From Release (Recommended)

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

- Security patterns (XSS vectors, unsafe APIs)
- Architecture layer violations
- Error handling patterns
- Naming conventions
- Transaction boundaries

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | All checks passed                |
| 2    | Issues found (operation blocked) |

## Configuration

Create `config.json` next to the binary or in `~/.config/guardrails/`:

```json
{
  "enabled": true,
  "rules": {
    "architecture": true,
    "errorHandling": true,
    "naming": true,
    "transaction": true,
    "consoleLog": true,
    "security": true,
    "biome": true
  },
  "severity": {
    "blockOn": ["critical", "high"]
  }
}
```

## License

MIT
