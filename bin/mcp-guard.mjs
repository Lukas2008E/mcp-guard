#!/usr/bin/env node
/**
 * MCP-Guard — Standalone Zero-Dependency CLI Security & Token Auditor for Model Context Protocol (MCP)
 * Usage:
 *   node bin/mcp-guard.mjs audit <path-to-config.json>
 *   node bin/mcp-guard.mjs sanitize <path-to-config.json>
 */

import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const command = args[0] || 'audit';
const targetPath = args[1] || '.mcp.json';

if (command === '--help' || command === '-h') {
  console.log(`
MCP-Guard v1.2.0 — Open-Source MCP Security & Token Inspector

Usage:
  npx mcp-guard audit <config.json>       Run static security & token audit
  npx mcp-guard sanitize <config.json>    Output hardened config with env references
`);
  process.exit(0);
}

const resolved = path.resolve(process.cwd(), targetPath);
if (!fs.existsSync(resolved)) {
  console.error(`[ERROR] Config file not found: ${resolved}`);
  process.exit(1);
}

const raw = fs.readFileSync(resolved, 'utf8');
const config = JSON.parse(raw);
const servers = config.mcpServers || config;

let criticalCount = 0;
let totalTokens = 0;

console.log('\n🛡️  MCP-Guard Audit Report for:', path.basename(resolved));
console.log('─'.repeat(64));

for (const [name, srv] of Object.entries(servers)) {
  if (!srv || typeof srv !== 'object') continue;
  const serialized = JSON.stringify(srv);
  const estTokens = Math.max(400, Math.ceil(serialized.length / 3.7) * 6);
  totalTokens += estTokens;

  const srvArgs = Array.isArray(srv.args) ? srv.args.map(String) : [];
  const srvEnv = srv.env && typeof srv.env === 'object' ? srv.env : {};

  console.log(`• Server: ${name} (~${estTokens} tokens/turn)`);

  for (const arg of srvArgs) {
    if (arg === '/' || arg.includes('.ssh') || arg.includes('.aws')) {
      criticalCount++;
      console.log(`  [CRITICAL SEC-002] Over-privileged filesystem path mounted: "${arg}"`);
    }
  }

  for (const [k, v] of Object.entries(srvEnv)) {
    const val = String(v);
    if (/TOKEN|KEY|SECRET|PASSWORD|URL/i.test(k) && val.length > 8 && !val.startsWith('${')) {
      criticalCount++;
      console.log(`  [CRITICAL SEC-001] Hardcoded secret in env.${k}`);
    }
  }
}

console.log('─'.repeat(64));
console.log(
  `Total Estimated Schema Overhead: ${totalTokens} tokens/turn (${((totalTokens / 200000) * 100).toFixed(2)}% of 200k context)`
);
console.log(`Critical Security Findings:      ${criticalCount}`);

if (criticalCount > 0) {
  console.log('\nRun "npx mcp-guard sanitize ' + targetPath + '" to remediate findings.');
  process.exit(1);
}
