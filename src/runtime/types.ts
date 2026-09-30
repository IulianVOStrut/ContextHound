import type { Severity, Confidence } from '../types.js';
import type { Rule } from '../rules/index.js';

export interface ContentPart {
  type: 'text' | 'image_url';
  text?: string;
  image_url?: { url: string };
}

export interface RuntimeMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | ContentPart[];
}

export interface RuntimeFinding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  evidence: string;
  remediation: string;
  riskPoints: number;
  /** Zero-based index of the message in the array that triggered this finding. */
  messageIndex: number;
  /** Role of that message ('system' | 'user' | 'assistant' | 'tool'). */
  messageRole: string;
}

export type GuardAction = 'block' | 'warn' | 'log' | 'allow';

export interface GuardPolicy {
  /** Action to take when a finding of this severity is found. Defaults to 'allow'. */
  critical?: GuardAction;
  high?: GuardAction;
  medium?: GuardAction;
  low?: GuardAction;
  /** Block if the aggregate score meets or exceeds this value (0 to 100). */
  blockThreshold?: number;
  /** Skip findings below this confidence level. */
  minConfidence?: Confidence;
  /** Rule IDs (or prefix globs like 'JBK*') to skip entirely. */
  excludeRules?: string[];
  /**
   * If set, only these rule IDs (or prefix globs) are run. Defaults to
   * RUNTIME_DEFAULT_RULES, the rules that apply to message content; the
   * static code rules (CMD, OUT, AGT, MCP, ...) are not meaningful on chat text.
   */
  includeRules?: string[];
}

export interface InspectResult {
  findings: RuntimeFinding[];
  /** Aggregate risk score (0-100), combined the same way as scan scores. */
  score: number;
  scoreLabel: 'low' | 'medium' | 'high' | 'critical';
  blocked: boolean;
  /** Wall-clock time the inspection took in milliseconds. */
  durationMs: number;
}

export interface GuardConfig {
  policy?: GuardPolicy;
  /** Called after every inspection, regardless of action. */
  onInspect?: (result: InspectResult, messages: RuntimeMessage[]) => void;
  /** Called only when the guard blocks a call. */
  onBlock?: (result: InspectResult, messages: RuntimeMessage[]) => void;
  /**
   * File-extension hint used to steer language-specific rules.
   * Defaults to 'ts'. Set to 'py' when inspecting Python agent calls.
   */
  languageHint?: 'ts' | 'js' | 'py' | 'go' | 'rs' | 'java';
  /** Additional custom rules to run alongside the built-in 86. */
  extraRules?: Rule[];
}

export class HoundBlockedError extends Error {
  constructor(
    public readonly result: InspectResult,
    public readonly messages: RuntimeMessage[],
  ) {
    super(
      `HoundGuard blocked: score=${result.score}, findings=${result.findings.length}`,
    );
    this.name = 'HoundBlockedError';
  }
}
