// ── Rule presets ──────────────────────────────────────────────────────────────
//
// A preset is a named bundle of rule-ID glob patterns (the same syntax accepted
// by `includeRules`). It lets teams enable a curated subset of rules without
// listing every ID — e.g. `hound scan --preset mcp`.

export interface Preset {
  description: string;
  /** Rule-ID patterns, e.g. ['INJ-*', 'RAG-*']. */
  rules: string[];
}

export const PRESETS: Record<string, Preset> = {
  'owasp-llm-top10': {
    description: 'Rules mapping to the OWASP Top 10 for LLM Applications',
    rules: ['INJ-*', 'JBK-*', 'EXF-*', 'OUT-*', 'RAG-*', 'TOOL-*', 'SCH-*', 'DOS-*', 'VIS-*'],
  },
  injection: {
    description: 'Prompt-injection and encoding-obfuscation rules',
    rules: ['INJ-*', 'RAG-*', 'ENC-*'],
  },
  jailbreak: {
    description: 'Jailbreak and system-instruction-override rules',
    rules: ['JBK-*'],
  },
  exfiltration: {
    description: 'Data-exfiltration and secret-leak rules',
    rules: ['EXF-*'],
  },
  agentic: {
    description: 'Agentic pipeline and Model Context Protocol rules',
    rules: ['AGT-*', 'MCP-*', 'TOOL-*'],
  },
  mcp: {
    description: 'Model Context Protocol security rules',
    rules: ['MCP-*'],
  },
  'supply-chain': {
    description: 'Dependency and model supply-chain rules',
    rules: ['SCH-*'],
  },
  'prompt-files': {
    description: 'Rules that apply to raw prompt/markdown files (no code analysis)',
    rules: ['INJ-*', 'JBK-*', 'EXF-*', 'ENC-*', 'SKL-*'],
  },
};

/**
 * Resolve one or more comma/space-separated preset names into a deduped list of
 * rule-ID patterns. Throws on an unknown preset so the CLI can report it.
 */
export function resolvePresets(names: string): string[] {
  const requested = names.split(/[, ]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  const out = new Set<string>();
  for (const name of requested) {
    const preset = PRESETS[name];
    if (!preset) {
      throw new Error(
        `Unknown preset "${name}". Available: ${Object.keys(PRESETS).join(', ')}.`,
      );
    }
    for (const r of preset.rules) out.add(r);
  }
  return [...out];
}
