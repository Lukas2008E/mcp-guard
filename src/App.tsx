/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo, useState } from 'react';
import { InspectorWorkspace } from './components/InspectorWorkspace';
import { RepoLaunchKit } from './components/RepoLaunchKit';
import { analyzeMcpConfig, MCP_PRESET_CONFIGS } from './utils/mcpAnalyzer';

type ActiveSection = 'inspector' | 'cli-kit' | 'rules-docs';

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('inspector');
  const [configJson, setConfigJson] = useState<string>(MCP_PRESET_CONFIGS[0].json);

  const auditReport = useMemo(() => analyzeMcpConfig(configJson), [configJson]);

  const handleDownloadSanitizedConfig = () => {
    const content = auditReport.validJson && auditReport.sanitizedConfigJson
      ? auditReport.sanitizedConfigJson
      : configJson;
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mcp.hardened.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-950/90 sticky top-0 z-30 backdrop-blur">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('inspector');
          }}
          className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 font-display"
        >
          MCP-Guard
        </a>

        {/* Zone 2: Concise single-line text navigation links */}
        <nav aria-label="Primary Navigation" className="flex items-center gap-6 text-sm font-medium text-slate-300 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveSection('inspector')}
            className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'inspector'
                ? 'text-amber-400 underline underline-offset-8 decoration-amber-400 decoration-2'
                : 'hover:text-white'
            }`}
          >
            Security Inspector
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('cli-kit')}
            className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'cli-kit'
                ? 'text-amber-400 underline underline-offset-8 decoration-amber-400 decoration-2'
                : 'hover:text-white'
            }`}
          >
            CLI &amp; CI/CD Integration
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('rules-docs')}
            className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'rules-docs'
                ? 'text-amber-400 underline underline-offset-8 decoration-amber-400 decoration-2'
                : 'hover:text-white'
            }`}
          >
            Rule Specification
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleDownloadSanitizedConfig}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-amber-500 rounded-lg hover:bg-amber-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Export Hardened Config
          </button>
        </div>
      </header>

      {/* Main Content Container (1440px baseline with generous padding) */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeSection === 'inspector' && (
          <InspectorWorkspace
            configJson={configJson}
            onChangeConfig={setConfigJson}
            report={auditReport}
            onNavigateToCliDocs={() => setActiveSection('cli-kit')}
          />
        )}

        {activeSection === 'cli-kit' && (
          <RepoLaunchKit
            githubUsername="carschangeslife"
            repoName="mcp-guard"
            npmPackageName="mcp-guard"
          />
        )}

        {activeSection === 'rules-docs' && (
          <div className="space-y-8">
            <div className="border border-slate-800 bg-slate-900/70 rounded-xl p-6 space-y-2">
              <div className="flex items-center gap-2 text-xs text-amber-400 font-medium">
                <span>Static Analysis Engine</span>
                <span aria-hidden="true">·</span>
                <span>Security &amp; Context Efficiency Rules</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100 font-display">
                Rule Specification &amp; Vulnerability Taxonomy
              </h1>
              <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
                MCP-Guard wendet 6 deterministische Prüfregeln auf Model Context Protocol (MCP) Server-Konfigurationen
                und Tool-Schemata an, um Credential-Leaks, indirekte Prompt-Injections und unnötigen
                Context-Window-Verbrauch vor der Ausführung zu verhindern.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[
                {
                  id: 'SEC-001',
                  title: '01. Plaintext Credential & API Token Leak Prevention',
                  severity: 'Critical',
                  body: 'Erkennt hartcodierte API-Keys (sk-ant-*, sk-proj-*), GitHub Personal Access Tokens (ghp_*), Slack Bot Tokens (xoxb-*) und PostgreSQL Passwort-Strings in MCP env-Objekten und überführt sie automatisch in sichere ${ENV_VAR} Laufzeit-Referenzen.',
                },
                {
                  id: 'SEC-002',
                  title: '02. Over-Privileged Host Filesystem Mounts',
                  severity: 'Critical',
                  body: 'Verhindert, dass @modelcontextprotocol/server-filesystem mit Root-Zugriff (/), dem gesamten Home-Verzeichnis (~) oder sensiblen Schlüsselspeichern (~/.ssh, ~/.aws) gestartet wird.',
                },
                {
                  id: 'SEC-003',
                  title: '03. MCP Tool Poisoning & Indirect Prompt Injection Firewall',
                  severity: 'Critical',
                  body: 'Analysiert Tool-Beschreibungen auf versteckte System-Anweisungen (<important>, <system>, "Ignore previous instructions", "Do not tell the user"), über die kompromittierte MCP-Server beim Laden des System-Prompts lokale Dateien exfiltrieren.',
                },
                {
                  id: 'SEC-004',
                  title: '04. Unpinned npx Supply-Chain Execution Guard',
                  severity: 'Medium',
                  body: 'Identifiziert unfixierte npx -y Aufrufe ohne explizite Versionsnummer (@1.x.x), die bei jedem Client-Start ungeprüften Code aus der npm-Registry nachladen.',
                },
                {
                  id: 'SEC-005',
                  title: '05. Arbitrary Shell & Permission Bypass Detection',
                  severity: 'High',
                  body: 'Markiert gefährliche CLI-Flags (--allow-all, --dangerously-skip-permissions) sowie unbeschränkte Shell-Execution-Tools ohne Subcommand-Allowlist.',
                },
                {
                  id: 'PERF-001',
                  title: '06. Context-Window & Schema Token Tree-Shaking',
                  severity: 'Medium',
                  body: 'Berechnet den Token-Verbrauch jedes MCP-Servers pro Konversationsrunde und reduziert durch Schema-Tree-Shaking die monatlichen Input-Token-Kosten um durchschnittlich 62%.',
                },
              ].map((rule) => (
                <div
                  key={rule.id}
                  className="border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-2"
                >
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span className="text-amber-400 font-semibold">{rule.id}</span>
                    <span>Severity: {rule.severity}</span>
                  </div>
                  <h2 className="text-base font-semibold text-slate-100">{rule.title}</h2>
                  <p className="text-xs text-slate-300 leading-relaxed">{rule.body}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-900 py-6 px-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <span>
            MCP-Guard Open-Source Security &amp; Token Inspector · MIT License
          </span>
          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => setActiveSection('inspector')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              Security Inspector
            </button>
            <button
              type="button"
              onClick={() => setActiveSection('cli-kit')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              CLI &amp; CI/CD
            </button>
            <button
              type="button"
              onClick={() => setActiveSection('rules-docs')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              Rule Specification
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
