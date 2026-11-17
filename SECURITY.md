# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

## Reporting a Vulnerability

If you discover a false negative or bypass in **MCP-Guard**'s static detection rules (`SEC-001` through `SEC-005`), such as a novel prompt-injection encoding or unflagged credential format:

1. Please **do not** open a public issue with live exploit payloads.
2. Open a private **GitHub Security Advisory** in this repository with a minimal reproducible `.mcp.json` snippet.
3. We aim to triage and release a rule signature patch within 48 hours.
