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
  category: 'injection' | 'exfiltration' | 'jailbreak' | 'unsafe-tools' | 'multimodal' | 'skills' | 'agentic' | 'mcp' | 'supply-chain' | 'dos';
  remediation: string;
  check(prompt: ExtractedPrompt, filePath: string): RuleMatch[];
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
  };
}
