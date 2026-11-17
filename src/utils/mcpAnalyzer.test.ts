import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMcpConfig, estimateTokensFromText, MCP_PRESET_CONFIGS } from './mcpAnalyzer';

test('estimateTokensFromText returns deterministic positive token count', () => {
  assert.equal(estimateTokensFromText(''), 0);
  const tokens = estimateTokensFromText('{"name":"read_file","description":"Reads a file from disk"}');
  assert.ok(tokens > 10 && tokens < 30);
});

test('analyzeMcpConfig detects critical secrets, root path mounts, and tool poisoning in vulnerable preset', () => {
  const vulnerablePreset = MCP_PRESET_CONFIGS.find((p) => p.id === 'vulnerable-production');
  assert.ok(vulnerablePreset, 'Vulnerable preset must exist');

  const report = analyzeMcpConfig(vulnerablePreset.json);
  assert.equal(report.validJson, true);
  assert.equal(report.serverCount, 4);
  assert.ok(report.findings.length >= 5, 'Should detect at least 5 security/token findings');

  // Verify SEC-001 (Secret leak)
  const secretFinding = report.findings.find((f) => f.ruleId === 'SEC-001');
  assert.ok(secretFinding, 'Must flag hardcoded API token');
  assert.equal(secretFinding.severity, 'critical');

  // Verify SEC-002 (Unrestricted filesystem)
  const fsFinding = report.findings.find((f) => f.ruleId === 'SEC-002');
  assert.ok(fsFinding, 'Must flag root or un-scoped home filesystem mount');

  // Verify SEC-003 (Tool poisoning)
  const poisonFinding = report.findings.find((f) => f.ruleId === 'SEC-003');
  assert.ok(poisonFinding, 'Must flag <important> prompt injection in tool description');

  // Verify sanitized output replaces hardcoded token with env reference
  assert.ok(
    report.sanitizedConfigJson.includes('${GITHUB_PERSONAL_ACCESS_TOKEN}'),
    'Sanitized config must replace literal GitHub token with env reference'
  );
  assert.ok(
    !report.sanitizedConfigJson.includes('ghp_9A8b7C6d5E4f3G2h1I0jKlMnOpQrStUvWxYz'),
    'Sanitized config must not leak literal GitHub token'
  );

  // Verify idempotent sanitization: re-analyzing sanitizedConfigJson achieves 100/100 score and 0 findings
  const reAnalyzed = analyzeMcpConfig(report.sanitizedConfigJson);
  assert.equal(reAnalyzed.securityScore, 100);
  assert.equal(reAnalyzed.findings.length, 0);
});

test('analyzeMcpConfig scores hardened preset at 100/100 with zero critical findings', () => {
  const hardenedPreset = MCP_PRESET_CONFIGS.find((p) => p.id === 'hardened-minimal');
  assert.ok(hardenedPreset);

  const report = analyzeMcpConfig(hardenedPreset.json);
  assert.equal(report.validJson, true);
  assert.equal(report.securityScore, 100);
  assert.equal(report.findings.length, 0);
  assert.ok(report.optimizedTotalTokens < report.totalSchemaTokens);
});

test('analyzeMcpConfig handles invalid JSON gracefully', () => {
  const report = analyzeMcpConfig('{ broken json ');
  assert.equal(report.validJson, false);
  assert.ok(report.errorMessage?.includes('JSON Parse Error'));
});
