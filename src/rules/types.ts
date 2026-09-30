import type { Finding, Severity, Confidence } from '../types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export interface RuleMatch {
  evidence: string;
  lineStart: number;
  lineEnd: number;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: 'injection' | 'exfiltration' | 'jailbreak' | 'unsafe-tools' | 'multimodal' | 'skills' | 'agentic' | 'mcp' | 'supply-chain' | 'dos' | 'persistence';
  mitre?: string;
  /** OWASP LLM Top 10 (LLM01-LLM10) and Agentic Top 10 (ASI01-ASI10) IDs. */
  owasp?: string[];
  remediation: string;
  /**
   * Also run on general documentation (README, changelogs, datasets), not just
   * prompt files and code. Only for rules whose match is suspicious in any text:
   * hidden characters, real secret values, hidden instructions.
   */
  docs?: boolean;
  check(prompt: ExtractedPrompt, filePath: string): RuleMatch[];
}

/**
 * Signs that a source file talks to an LLM: provider SDKs, chat completion
 * calls or prompt-building. Rules about handling model output use it so they
 * do not fire on ordinary code (a config loader calling JSON.parse(text)).
 */
export const LLM_CONTEXT =
  /(?:openai|anthropic|gemini|mistral|cohere|ollama|bedrock|langchain|llamaindex|\.chat\.completions|\.messages\.create|\.responses\.create|generateText|streamText|generateObject|createCompletion|chatCompletion|\bcompletion\b|\bllm\b|systemPrompt|messages\s*(?:\??\.)?\s*push)/i;

/** The first line of `prompt` matching `pattern`, as a RuleMatch, or null. */
export function firstMatchingLine(prompt: ExtractedPrompt, pattern: RegExp): RuleMatch | null {
  const lines = prompt.text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      return { evidence: lines[i].trim(), lineStart: prompt.lineStart + i, lineEnd: prompt.lineStart + i };
    }
  }
  return null;
}

/** Escape text for literal use inside a RegExp built from scanned content. */
export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
};

const CONFIDENCE_MULTIPLIERS: Record<Confidence, number> = {
  low: 0.5,
  medium: 0.75,
  high: 1.0,
};

export function calcRiskPoints(severity: Severity, confidence: Confidence): number {
  return Math.round(SEVERITY_WEIGHTS[severity] * CONFIDENCE_MULTIPLIERS[confidence]);
}

export function ruleToFinding(rule: Rule, match: RuleMatch, filePath: string): Finding {
  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence,
    evidence: match.evidence.slice(0, 200),
    file: filePath,
    lineStart: match.lineStart,
    lineEnd: match.lineEnd,
    remediation: rule.remediation,
    riskPoints: calcRiskPoints(rule.severity, rule.confidence),
    ...(rule.mitre !== undefined && { mitre: rule.mitre }),
    ...(rule.owasp?.length && { owasp: rule.owasp }),
  };
}
