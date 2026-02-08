# agent-wars

Multi-agent security testing CLI tool. Three AI agents battle-test your codebase:

- **Red Agent** - Finds security vulnerabilities
- **Blue Agent** - Applies automatic fixes
- **Green Agent** - Orchestrates and referees the process

Built with Claude Agent SDK.

## Requirements

- Node.js 18+
- `ANTHROPIC_API_KEY` environment variable set

## Install

```bash
npm install -g agent-wars
```

## Usage

```bash
# Scan a project
agent-wars scan -t ./my-project

# Scan with options
agent-wars scan -t ./my-project -o ./report -i 5 --no-fix

# Use a specific model
agent-wars scan -t ./my-project -m claude-sonnet-4-5-20250929
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target <path>` | Target project directory | (required) |
| `-o, --output <path>` | Report output directory | `./agent-wars-report` |
| `-i, --max-iterations <n>` | Max Red/Blue rounds | `3` |
| `-s, --severity <level>` | Min severity: critical\|high\|medium\|low\|info | `low` |
| `--fix / --no-fix` | Apply automatic fixes | `true` |
| `-m, --model <model>` | Claude model to use | `claude-sonnet-4-5-20250929` |
| `-b, --budget <usd>` | Max API budget in USD | `5` |
| `-v, --verbose` | Verbose output | `false` |

## How It Works

1. **Red Agent** scans your codebase for vulnerabilities (OWASP Top 10, injection, auth issues, etc.)
2. **Blue Agent** analyzes found vulnerabilities and applies fixes
3. **Green Agent** orchestrates multiple rounds until all issues are resolved or max iterations reached
4. HTML + JSON reports are generated with full details

## License

MIT
