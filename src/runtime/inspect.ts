import type { ExtractedPrompt } from '../scanner/extractor.js';
import { analyzePrompt, combineRisk, scoreLabel } from '../scoring/index.js';
import type { Rule } from '../rules/index.js';
import type { AuditConfig, Confidence } from '../types.js';
import type {
  ContentPart,
  RuntimeMessage,
  RuntimeFinding,
  GuardPolicy,
  InspectResult,
} from './types.js';

/**
 * Rules the guard runs on live messages by default: jailbreak phrases,
 * encoding and steganography, system-prompt extraction, secret values and
 * hidden comment instructions. Code rules would flag ordinary chat text.
 */
export const RUNTIME_DEFAULT_RULES = ['JBK-*', 'ENC-*', 'EXF-002', 'EXF-007', 'EXF-008', 'INJ-006'];

/** Flatten ContentPart[] or a plain string into a single text string. */
function extractText(content: string | ContentPart[]): string {
  if (typeof content === 'string') return content;
  return content
    .filter(
      (p): p is ContentPart & { text: string } =>
        p.type === 'text' && typeof p.text === 'string',
    )
    .map(p => p.text)
    .join('\n');
}

/**
 * Convert a messages array to findings.
 *
 * Each message is analysed independently so that:
 * - The deduplication key (`ruleId:filePath:lineStart`) is unique per message.
 * - The `messageIndex` on each finding maps back to the original array.
 *
 * Every message is emitted as both `raw` (for content-scanning rules: JBK, EXF,
 * ENC, INJ) and `code-block` (for multi-line context rules: AGT, RAG, CMD, OUT,
 * MCP).  Because rules gate on `prompt.kind`, emitting both kinds does not double
 * the findings: each rule fires on exactly the kind it expects.
 */
export function runInspect(
  messages: RuntimeMessage[],
  policy: GuardPolicy | undefined,
  languageHint: string,
  extraRules: Rule[] | undefined,
): Omit<InspectResult, 'blocked' | 'durationMs'> {
  const config: Pick<AuditConfig, 'excludeRules' | 'includeRules' | 'minConfidence'> = {
    excludeRules: policy?.excludeRules,
    // Custom rules passed to the guard always run alongside the defaults.
    includeRules: policy?.includeRules ?? [...RUNTIME_DEFAULT_RULES, ...(extraRules ?? []).map(r => r.id)],
    minConfidence: policy?.minConfidence as Confidence | undefined,
  };

  const allFindings: RuntimeFinding[] = [];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const text = extractText(msg.content);
    if (!text.trim()) continue;

    // Unique synthetic path per message: keeps the dedup namespace separate
    // across messages and lets rules that gate on path.extname() fire correctly.
    const syntheticPath = `_hound_msg_${i}.${languageHint}`;

    const lines = text.split('\n');
    const prompts: ExtractedPrompt[] = [
      { text, lineStart: 1, lineEnd: lines.length, kind: 'raw' },
      { text, lineStart: 1, lineEnd: lines.length, kind: 'code-block' },
    ];

    const findings = analyzePrompt(prompts, syntheticPath, config, extraRules);

    for (const f of findings) {
      allFindings.push({
        id: f.id,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        evidence: f.evidence,
        remediation: f.remediation,
        riskPoints: f.riskPoints,
        messageIndex: i,
        messageRole: msg.role,
      });
    }
  }

  // Each rule counts once, at its highest points, as in file scoring.
  const perRule = new Map<string, number>();
  for (const f of allFindings) perRule.set(f.id, Math.max(perRule.get(f.id) ?? 0, f.riskPoints));
  const score = combineRisk([...perRule.values()]);

  return { findings: allFindings, score, scoreLabel: scoreLabel(score) };
}

/** Evaluate the policy to determine whether this result should be blocked. */
export function evaluateBlocked(
  findings: RuntimeFinding[],
  score: number,
  policy: GuardPolicy | undefined,
): boolean {
  if (!policy) return false;

  if (policy.blockThreshold != null && score >= policy.blockThreshold) return true;

  return findings.some(f => {
    const action = policy[f.severity];
    return action === 'block';
  });
}
