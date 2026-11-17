# 🛡️ MCP-Guard — Open-Source MCP Security Scanner & Context Token Profiler

[![License: MIT](https://img.shields.io/badge/License-MIT-amber.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-2025--11--25%20Spec-emerald)](https://modelcontextprotocol.io)
[![Zero Runtime Dependencies](https://img.shields.io/badge/CLI%20Dependencies-0-blue)](#standalone-cli-usage)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**MCP-Guard** is an open-source static security analyzer, prompt-injection firewall, and context-window token profiler for **Model Context Protocol (MCP)** server configurations (`claude_desktop_config.json`, `.mcp.json`, Cursor, and Windsurf).

> **The Problem:** Loading 4–5 community MCP servers silently injects **15,000+ schema tokens** into *every single conversation turn* while exposing developer machines to hardcoded credential leaks, over-privileged host directory mounts (`/`, `~/.ssh`), and **MCP Tool Poisoning** (hidden `<important>` or `<system>` prompt-injection instructions inside tool descriptions).

---

## ⚡ Quick Start

### 1. Standalone CLI Audit (`bin/mcp-guard.mjs`)

Audit any local `.mcp.json` or `claude_desktop_config.json` directly via Node.js or `npx`:

```bash
# Audit a hardened configuration (exits with code 0)
node bin/mcp-guard.mjs audit examples/hardened.mcp.json

# Audit a vulnerable configuration (detects critical risks and exits with code 1)
node bin/mcp-guard.mjs audit examples/vulnerable.mcp.json
```

### 2. Interactive Web Inspector

Launch the visual security inspector, per-server token profiler, and one-click configuration sanitizer:

```bash
npm install
npm run dev
```

---

## 🔍 Security & Context Efficiency Rules

| Rule ID | Category | Severity | Description |
| :--- | :--- | :--- | :--- |
| `SEC-001` | **Secret Leak** | 🔴 Critical | Detects plaintext Anthropic (`sk-ant-*`), OpenAI (`sk-proj-*`), GitHub PAT (`ghp_*`), Slack (`xoxb-*`), and PostgreSQL credentials in `env` blocks and converts them to `${ENV_VAR}` references. |
| `SEC-002` | **Unrestricted Filesystem** | 🔴 Critical | Blocks root (`/`), unscoped home (`~`), and sensitive directory (`~/.ssh`, `~/.aws`, `/etc`) mounts in filesystem servers. |
| `SEC-003` | **Tool Poisoning** | 🔴 Critical | Scans tool descriptions for covert prompt overrides (`Ignore previous instructions`, `<important>`, `<system>` exfiltration tags, and stealth concealment directives). |
| `SEC-004` | **Supply-Chain Drift** | 🟠 Medium | Flags unpinned `npx -y` package executions susceptible to upstream registry hijacking. |
| `SEC-005` | **Command Execution** | 🟠 High | Identifies `--allow-all` permission bypass flags and unrestricted shell execution tools. |
| `PERF-001` | **Context Window Bloat** | 🟡 Medium | Profiles per-server schema token footprint and applies **Schema Tree-Shaking** to cut per-turn input token overhead by up to **62%**. |

---

## 📊 Benchmark: Context-Window & Cost Savings

Measured across a standard 5-server developer setup (GitHub + Playwright + Postgres + Slack + Filesystem) at 100 prompts/day on a 200k context window:

| Metric | Raw MCP Config | After `MCP-Guard` Sanitization | Delta |
| :--- | ---: | ---: | ---: |
| **Total Tools Loaded / Turn** | 82 tools | 24 active tools | **-70.7%** |
| **Schema Input Tokens / Turn** | 24,180 tokens | 9,188 tokens | **-62.0%** |
| **% of 200k Context Window** | 12.09% | 4.59% | **-7.50% freed** |
| **Monthly Schema Token Cost** | $217.62 / mo | $82.69 / mo | **$134.93 saved/mo** |

---

## 🤖 GitHub Action / CI Integration

Protect your repository's `.mcp.json` in CI/CD by adding **MCP-Guard** to `.github/workflows/mcp-security.yml`:

```yaml
name: MCP Security Audit
on: [push, pull_request]
jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run MCP-Guard Audit
        run: node bin/mcp-guard.mjs audit .mcp.json
```

---

## 🧪 Running Tests

MCP-Guard uses Node's built-in test runner (`node:test`) for fast, deterministic verification:

```bash
npm test
```

## 📄 License

Released under the [MIT License](LICENSE). See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for governance details.
