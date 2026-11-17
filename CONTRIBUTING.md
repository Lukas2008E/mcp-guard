# Contributing to MCP-Guard

Thank you for helping secure and optimize the **Model Context Protocol (MCP)** ecosystem!

## Architecture Overview

- `src/utils/mcpAnalyzer.ts` — Core zero-dependency static security & token profiling engine (`SEC-001` to `SEC-005` and `PERF-001`).
- `src/utils/mcpAnalyzer.test.ts` — Deterministic unit test suite using Node's built-in test runner (`node:test`).
- `bin/mcp-guard.mjs` — Standalone Node.js CLI binary for terminal and CI/CD execution (`npx mcp-guard audit`).
- `src/components/` — Interactive Web Inspector UI for visual auditing and one-click configuration hardening.

## Adding a New Security Signature or Server Profile

1. Fork the repository and create a feature branch (`git checkout -b feat/new-rule`).
2. Add your regex signature or server token profile in `src/utils/mcpAnalyzer.ts`.
3. Add a deterministic unit test in `src/utils/mcpAnalyzer.test.ts`.
4. Run the test suite and typechecker:
   ```bash
   npm test
   npm run lint
   ```
5. Open a Pull Request describing the vulnerability class or token optimization.
