import React, { useState } from 'react';
import { Check, Copy, Download, FileCode2, FolderGit2, Terminal } from 'lucide-react';
import { generateRepoBundle, RepoFileArtifact } from '../utils/repoBundleGenerator';

interface RepoLaunchKitProps {
  githubUsername: string;
  repoName: string;
  npmPackageName: string;
}

export const RepoLaunchKit: React.FC<RepoLaunchKitProps> = ({
  githubUsername,
  repoName,
  npmPackageName,
}) => {
  const files: RepoFileArtifact[] = generateRepoBundle(
    githubUsername,
    repoName,
    npmPackageName
  );
  const [selectedFilePath, setSelectedFilePath] = useState<string>(files[0].path);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  const activeFile = files.find((f) => f.path === selectedFilePath) || files[0];

  const handleCopyFile = async (file: RepoFileArtifact) => {
    try {
      await navigator.clipboard.writeText(file.content);
      setCopiedPath(file.path);
      setTimeout(() => setCopiedPath(null), 2000);
    } catch {
      // Fallback
    }
  };

  const handleDownloadFile = (file: RepoFileArtifact) => {
    const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.path.replace(/\//g, '_');
    a.click();
    URL.revokeObjectURL(url);
  };

  const gitInitCommands = `# 1. Run standalone security & token audit via npx
npx ${npmPackageName || 'mcp-guard'} audit .mcp.json

# 2. Generate a hardened, token-optimized MCP configuration
npx ${npmPackageName || 'mcp-guard'} sanitize .mcp.json --output .mcp.hardened.json

# 3. Run local Node.js CLI binary directly from repository
node bin/mcp-guard.mjs audit ~/.config/Claude/claude_desktop_config.json`;

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="border border-slate-800 bg-slate-900/70 rounded-xl p-6">
        <div className="space-y-2 max-w-3xl">
          <div className="flex items-center gap-2 text-xs text-amber-400 font-medium">
            <span>CLI &amp; CI/CD Integration</span>
            <span aria-hidden="true">·</span>
            <span>Zero-Dependency Node.js Runner &amp; GitHub Actions</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100 font-display">
            Standalone CLI, GitHub Action &amp; Repository Files
          </h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            Integriere <strong>MCP-Guard</strong> direkt in deine lokale Entwicklungsumgebung oder als automatisierten
            Sicherheits-Check in deine CI/CD-Pipeline. Hier findest du das ausführbare CLI-Skript (
            <code className="text-amber-300 font-mono text-xs">bin/mcp-guard.mjs</code>), den GitHub Actions Workflow (
            <code className="text-amber-300 font-mono text-xs">.github/workflows/ci.yml</code>) sowie die Projektdokumentation.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 4 Columns: File Tree Selector & Terminal Push Commands */}
        <div className="lg:col-span-4 space-y-6">
          <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <FolderGit2 className="w-4 h-4 text-amber-400" />
              <span>Repository-Artefakte auswählen</span>
            </div>
            <div className="space-y-2">
              {files.map((file) => {
                const isSelected = file.path === activeFile.path;
                return (
                  <button
                    key={file.path}
                    type="button"
                    onClick={() => setSelectedFilePath(file.path)}
                    className={`w-full text-left p-3 rounded-lg border transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800 border-amber-500/60 text-slate-100'
                        : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-semibold text-amber-300">
                        {file.path}
                      </span>
                      <FileCode2 className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{file.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* CLI Quick-Start Commands */}
          <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>CLI Quick-Start Commands</span>
              </div>
              <button
                type="button"
                onClick={() =>
                  handleCopyFile({
                    path: 'git-commands',
                    title: 'Git Commands',
                    language: 'markdown',
                    description: '',
                    content: gitInitCommands,
                  })
                }
                className="px-2.5 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {copiedPath === 'git-commands' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    Kopiert
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    Befehle kopieren
                  </>
                )}
              </button>
            </div>
            <pre className="text-[11px] font-mono leading-relaxed bg-slate-950 border border-slate-800 rounded-lg p-3.5 text-slate-300 overflow-x-auto">
              {gitInitCommands}
            </pre>
          </div>
        </div>

        {/* Right 8 Columns: File Preview & Export Actions */}
        <div className="lg:col-span-8 border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h2 className="text-base font-semibold text-slate-100 font-mono">
                {activeFile.title}
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">{activeFile.description}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => handleCopyFile(activeFile)}
                className="px-3 py-1.5 text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {copiedPath === activeFile.path ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    Datei kopiert
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Datei-Inhalt kopieren
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => handleDownloadFile(activeFile)}
                className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Herunterladen
              </button>
            </div>
          </div>

          <pre className="w-full font-mono text-xs leading-relaxed bg-slate-950 text-slate-200 border border-slate-800 rounded-lg p-4 overflow-x-auto max-h-[620px]">
            {activeFile.content}
          </pre>
        </div>
      </div>
    </div>
  );
};
