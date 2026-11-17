import React, { useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Download,
  FileCode,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  Zap,
  Terminal,
} from 'lucide-react';
import {
  AuditReport,
  MCP_PRESET_CONFIGS,
  RiskSeverity,
  SecurityFinding,
} from '../utils/mcpAnalyzer';

interface InspectorWorkspaceProps {
  configJson: string;
  onChangeConfig: (nextJson: string) => void;
  report: AuditReport;
  onNavigateToCliDocs: () => void;
}

export const InspectorWorkspace: React.FC<InspectorWorkspaceProps> = ({
  configJson,
  onChangeConfig,
  report,
  onNavigateToCliDocs,
}) => {
  const [selectedPresetId, setSelectedPresetId] = useState<string>('vulnerable-production');
  const [severityFilter, setSeverityFilter] = useState<'all' | RiskSeverity>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeCodeTab, setActiveCodeTab] = useState<'raw' | 'sanitized'>('raw');
  const [copiedSanitized, setCopiedSanitized] = useState(false);
  const [autoFixNotice, setAutoFixNotice] = useState<string | null>(null);

  const handleSelectPreset = (presetId: string) => {
    const preset = MCP_PRESET_CONFIGS.find((p) => p.id === presetId);
    if (preset) {
      setSelectedPresetId(presetId);
      onChangeConfig(preset.json);
      setActiveCodeTab('raw');
      setAutoFixNotice(null);
    }
  };

  const handleApplySanitizedConfig = () => {
    if (!report.validJson || !report.sanitizedConfigJson) return;
    onChangeConfig(report.sanitizedConfigJson);
    setActiveCodeTab('raw');
    setAutoFixNotice(
      'Hardened configuration applied: Plaintext secrets replaced with ${ENV_VAR} references, dangerous root mounts scoped to ./workspace-sandbox, and poisoned tool tags stripped.'
    );
  };

  const handleCopyConfig = async (textToCopy: string) => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      setCopiedSanitized(true);
      setTimeout(() => setCopiedSanitized(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleDownloadReportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mcp-guard-audit-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredFindings = report.findings.filter((f: SecurityFinding) => {
    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesSearch =
      !searchQuery.trim() ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.serverName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const criticalCount = report.findings.filter((f) => f.severity === 'critical').length;
  const highCount = report.findings.filter((f) => f.severity === 'high').length;

  return (
    <div className="space-y-8">
      {/* Top Executive Context Banner */}
      <div className="border border-slate-800 bg-slate-900/70 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2 text-xs text-amber-400 font-medium">
              <span>Static Security &amp; Schema Profiler</span>
              <span aria-hidden="true">·</span>
              <span>MCP Specification 2025-11-25</span>
              <span aria-hidden="true">·</span>
              <span>Zero External Runtime Dependencies</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100 font-display">
              MCP-Guard Security Firewall &amp; Context Token Profiler
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              Statische Sicherheitsanalyse und Context-Window-Profilierung für Model Context Protocol (MCP) Server:
              Scannt <code className="text-amber-300 font-mono text-xs">.mcp.json</code> und Desktop-Konfigurationen
              auf versteckte <strong>Prompt-Injections (Tool Poisoning)</strong>, Klartext-Credentials sowie
              unbeschränkte Host-Dateisystem-Mounts und berechnet den exakten Schema-Token-Overhead pro Konversationsrunde.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleApplySanitizedConfig}
              disabled={!report.validJson || report.findings.length === 0}
              className="px-4 py-2.5 text-xs font-semibold bg-amber-500 hover:bg-amber-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer disabled:cursor-not-allowed"
            >
              <Wrench className="w-4 h-4" />
              Auto-Sanitize Config ({report.findings.length} Fixes)
            </button>
            <button
              type="button"
              onClick={onNavigateToCliDocs}
              className="px-4 py-2.5 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Terminal className="w-4 h-4 text-amber-400" />
              CLI &amp; GitHub Action einrichten
            </button>
          </div>
        </div>

        {autoFixNotice && (
          <div
            role="status"
            className="mt-4 p-3.5 rounded-lg bg-emerald-950/60 border border-emerald-700/60 text-emerald-200 text-xs flex items-center justify-between gap-4"
          >
            <div className="flex items-center gap-2.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{autoFixNotice}</span>
            </div>
            <button
              type="button"
              onClick={() => setAutoFixNotice(null)}
              className="text-emerald-300 hover:text-white underline text-xs whitespace-nowrap shrink-0"
            >
              Ausblenden
            </button>
          </div>
        )}
      </div>

      {/* 4-Column Quantitative KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="border border-slate-800 bg-slate-900/50 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Security Audit Score</span>
            <ShieldAlert className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span
              data-testid="security-score-value"
              className={`text-3xl font-bold font-mono tabular-nums ${
                report.securityScore >= 85
                  ? 'text-emerald-400'
                  : report.securityScore >= 50
                    ? 'text-amber-400'
                    : 'text-rose-400'
              }`}
            >
              {report.securityScore}/100
            </span>
            <span className="text-xs text-slate-400">
              {criticalCount > 0 ? `${criticalCount} Critical · ${highCount} High` : 'Zero Critical Risks'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Geprüft über {report.serverCount} konfigurierte MCP-Server ({report.totalTools} Tools)
          </p>
        </div>

        <div className="border border-slate-800 bg-slate-900/50 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Schema Token Footprint / Turn</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono tabular-nums text-slate-100">
              {report.totalSchemaTokens.toLocaleString()}
            </span>
            <span className="text-xs text-slate-400 font-mono tabular-nums">
              ({report.contextPercentUsed}% von 200k)
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Nach Tree-Shaking:{' '}
            <strong className="text-emerald-400 font-mono tabular-nums">
              {report.optimizedTotalTokens.toLocaleString()} Tokens
            </strong>{' '}
            (-62% Overhead)
          </p>
        </div>

        <div className="border border-slate-800 bg-slate-900/50 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Monatliche Schema-Kosten (100 Turns/Tag)</span>
            <FileCode className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono tabular-nums text-slate-100">
              ${report.monthlyCostAt100DailyTurnsUsd.toFixed(2)}
            </span>
            <span className="text-xs text-emerald-400 font-mono tabular-nums">
              -${report.monthlySavingsUsd.toFixed(2)}/Mo sparbar
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Berechnet auf Basis von Claude Sonnet ($3.00 / 1M Input-Tokens)
          </p>
        </div>

        <div className="border border-slate-800 bg-slate-900/50 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Aktive Sicherheitsbefunde</span>
            <Lock className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span
              data-testid="findings-count-value"
              className="text-3xl font-bold font-mono tabular-nums text-slate-100"
            >
              {report.findings.length}
            </span>
            <span className="text-xs text-slate-400">Regelverstöße erkannt</span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            SEC-001 (Secrets) · SEC-002 (Paths) · SEC-003 (Poisoning)
          </p>
        </div>
      </div>

      {/* Main 2-Column Workspace: Left Config Editor & Preset Selector | Right Live Findings & Token Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Config Input & Sanitizer (5 cols) */}
        <div className="lg:col-span-5 border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                1. MCP Konfigurations-Quelle
              </h2>
              <p className="text-xs text-slate-400">
                Wähle ein reales Benchmark-Preset oder füge deine eigene <code className="font-mono">.mcp.json</code> ein
              </p>
            </div>
            <button
              type="button"
              onClick={handleDownloadReportJson}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              JSON Report
            </button>
          </div>

          {/* Preset Selector Buttons */}
          <div className="space-y-2" role="group" aria-label="Benchmark Configuration Presets">
            {MCP_PRESET_CONFIGS.map((preset) => {
              const isSelected = selectedPresetId === preset.id;
              return (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => handleSelectPreset(preset.id)}
                  className={`w-full text-left p-3 rounded-lg border transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-slate-800/90 border-amber-500/60 text-slate-100'
                      : 'bg-slate-950/60 border-slate-800/80 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-100">{preset.name}</span>
                    <span className="text-xs text-amber-400 font-mono whitespace-nowrap shrink-0">
                      {preset.subtitle.split('·')[0]}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-1">{preset.description}</p>
                </button>
              );
            })}
          </div>

          {/* Segmented View Toggle: Raw vs Sanitized */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-800">
            <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800">
              <button
                type="button"
                onClick={() => setActiveCodeTab('raw')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeCodeTab === 'raw'
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Aktuelle Config (Editierbar)
              </button>
              <button
                type="button"
                onClick={() => setActiveCodeTab('sanitized')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeCodeTab === 'sanitized'
                    ? 'bg-slate-800 text-emerald-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Hardened Output (Vorschau)
              </button>
            </div>

            <button
              type="button"
              onClick={() =>
                handleCopyConfig(activeCodeTab === 'raw' ? configJson : report.sanitizedConfigJson)
              }
              className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedSanitized ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  Kopiert
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Config kopieren
                </>
              )}
            </button>
          </div>

          {activeCodeTab === 'raw' ? (
            <div>
              <label htmlFor="mcp-json-editor" className="sr-only">
                MCP Configuration JSON Editor
              </label>
              <textarea
                id="mcp-json-editor"
                value={configJson}
                onChange={(e) => onChangeConfig(e.target.value)}
                rows={16}
                spellCheck={false}
                className="w-full font-mono text-xs leading-relaxed bg-slate-950 text-slate-200 border border-slate-800 rounded-lg p-3.5 focus:outline-none focus:border-amber-500"
                placeholder='{"mcpServers": { ... }}'
              />
            </div>
          ) : (
            <div>
              <pre className="w-full font-mono text-xs leading-relaxed bg-slate-950 text-emerald-300 border border-emerald-900/50 rounded-lg p-3.5 overflow-x-auto max-h-[380px]">
                {report.sanitizedConfigJson || '// Ungültiges JSON'}
              </pre>
            </div>
          )}

          {!report.validJson && (
            <div
              role="alert"
              className="p-3 rounded-lg bg-rose-950/70 border border-rose-700 text-rose-200 text-xs flex items-center gap-2"
            >
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{report.errorMessage}</span>
            </div>
          )}
        </div>

        {/* Right Column: Security Advisories & Per-Server Token Table (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Per-Server Token & Cost Breakdown Table */}
          <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-slate-100">
                  2. Claude Context-Window &amp; Schema-Token-Profil pro Server
                </h2>
                <p className="text-xs text-slate-400">
                  Zeigt den unsichtbaren System-Prompt-Overhead jedes MCP-Servers bei jedem einzelnen Aufruf
                </p>
              </div>
              <span className="text-xs text-slate-400 font-mono tabular-nums">
                Basis: 200.000 Context Window
              </span>
            </div>

            {report.serverProfiles.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg text-xs text-slate-400">
                Keine MCP-Server in der Konfiguration gefunden. Wähle links ein Preset aus.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-xs text-slate-400">
                      <th className="py-2.5 pr-4 font-medium">Server Name</th>
                      <th className="py-2.5 px-3 font-medium text-right">Tools</th>
                      <th className="py-2.5 px-3 font-medium text-right">Schema Tokens</th>
                      <th className="py-2.5 px-3 font-medium text-right">Nach Tree-Shaking</th>
                      <th className="py-2.5 px-3 font-medium text-right">Kosten / 1k Turns</th>
                      <th className="py-2.5 pl-3 font-medium text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs">
                    {report.serverProfiles.map((srv) => (
                      <tr key={srv.serverName} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 pr-4 font-mono font-medium text-slate-200">
                          {srv.serverName}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-300">
                          {srv.toolCount}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-200">
                          {srv.estimatedSchemaTokens.toLocaleString()}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums text-emerald-400">
                          {srv.optimizedTokensAfterTrim.toLocaleString()}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-300">
                          ${srv.costPer1kSessionsUsd.toFixed(2)}
                        </td>
                        <td className="py-3 pl-3 text-right">
                          <span
                            className={`font-medium ${
                              srv.riskStatus === 'critical'
                                ? 'text-rose-400'
                                : srv.riskStatus === 'warning'
                                  ? 'text-amber-400'
                                  : 'text-emerald-400'
                            }`}
                          >
                            {srv.riskStatus === 'critical'
                              ? 'Critical Risk'
                              : srv.riskStatus === 'warning'
                                ? 'Warning'
                                : 'Hardened'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Security Findings List with Interactive Filter Controls */}
          <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-slate-100">
                  3. Erkannte Sicherheits- &amp; Architektur-Befunde ({filteredFindings.length})
                </h2>
                <p className="text-xs text-slate-400">
                  Statische Regel-Analyse für Credentials, Host-Mounts und Tool-Poisoning
                </p>
              </div>

              {/* Interactive Filter Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800">
                  {(['all', 'critical', 'high', 'medium'] as const).map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => setSeverityFilter(sev)}
                      className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        severityFilter === sev
                          ? 'bg-slate-800 text-slate-100'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {sev === 'all' ? 'Alle' : sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </button>
                  ))}
                </div>
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Befunde filtern..."
                  aria-label="Sicherheitsbefunde durchsuchen"
                  className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500 w-40"
                />
              </div>
            </div>

            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg space-y-2">
                <ShieldCheck className="w-7 h-7 text-emerald-400 mx-auto" />
                <p className="text-sm font-semibold text-slate-200">
                  Keine Befunde für diesen Filter vorhanden
                </p>
                <p className="text-xs text-slate-400">
                  Deine Konfiguration erfüllt alle geprüften Sicherheitsregeln oder der aktive Filter blendet Einträge aus.
                </p>
                {severityFilter !== 'all' && (
                  <button
                    type="button"
                    onClick={() => {
                      setSeverityFilter('all');
                      setSearchQuery('');
                    }}
                    className="mt-2 px-3 py-1.5 text-xs font-medium text-amber-400 hover:underline inline-flex items-center gap-1"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    Filter zurücksetzen
                  </button>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="p-4 rounded-lg border border-slate-800 bg-slate-950/70 space-y-2"
                  >
                    {/* Unboxed clean metadata row with middle-dot separators */}
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2 text-slate-400 font-mono">
                        <span
                          className={`font-semibold ${
                            finding.severity === 'critical'
                              ? 'text-rose-400'
                              : finding.severity === 'high'
                                ? 'text-amber-400'
                                : 'text-sky-400'
                          }`}
                        >
                          {finding.severity.toUpperCase()}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span>{finding.ruleId}</span>
                        <span aria-hidden="true">·</span>
                        <span>{finding.category}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-slate-300">Server: {finding.serverName}</span>
                      </div>
                      <span className="text-xs font-mono text-slate-400">{finding.target}</span>
                    </div>

                    <h3 className="text-sm font-semibold text-slate-100">{finding.title}</h3>
                    <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
                    <div className="pt-1 text-xs text-emerald-300/90">
                      <strong className="font-medium text-emerald-400">Empfohlene Behebung: </strong>
                      {finding.remediation}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
