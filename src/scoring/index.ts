import type { Finding, FileResult, ScanResult, Severity, AuditConfig, Confidence } from '../types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';
import { allRules, ruleToFinding, scoreMitigations, mitigationReductionFor } from '../rules/index.js';
import type { Rule } from '../rules/index.js';

export function scoreLabel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score < 30) return 'low';
  if (score < 60) return 'medium';
  if (score < 80) return 'high';
  return 'critical';
}

function matchesFilter(id: string, pattern: string): boolean {
  return pattern.endsWith('*')
    ? id.startsWith(pattern.slice(0, -1))
    : id === pattern;
}

export function analyzePrompt(
  prompts: ExtractedPrompt[],
  filePath: string,
  config?: Pick<AuditConfig, 'excludeRules' | 'includeRules' | 'minConfidence'>,
  extraRules?: Rule[]
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const confidenceOrder: Confidence[] = ['low', 'medium', 'high'];
  const ruleset = extraRules ? [...allRules, ...extraRules] : allRules;

  for (const prompt of prompts) {
    // Get mitigations for this prompt
    const mitigation = scoreMitigations(prompt);

    for (const rule of ruleset) {
      // Apply rule filters
      if (config?.excludeRules?.some(p => matchesFilter(rule.id, p))) continue;
      if (config?.includeRules?.length &&
          !config.includeRules.some(p => matchesFilter(rule.id, p))) continue;
      if (config?.minConfidence) {
        if (confidenceOrder.indexOf(rule.confidence) < confidenceOrder.indexOf(config.minConfidence)) continue;
      }

      const matches = rule.check(prompt, filePath);
      for (const match of matches) {
        const key = `${rule.id}:${filePath}:${match.lineStart}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const finding = ruleToFinding(rule, match, filePath);

        // Apply only the mitigations relevant to this rule's category, so an
        // unrelated guard (e.g. a tool allowlist) can't dampen this finding.
        const reduction = mitigationReductionFor(mitigation, rule.id) / 100;
        finding.riskPoints = Math.max(1, Math.round(finding.riskPoints * (1 - reduction)));

        findings.push(finding);
      }
    }
  }

  return findings;
}

export function scoreFile(findings: Finding[]): number {
  return findings.reduce((sum, f) => sum + f.riskPoints, 0);
}

export function buildScanResult(
  fileResults: FileResult[],
  config: AuditConfig
): ScanResult {
  const allFindings = fileResults.flatMap(f => f.findings);

  // Cap total raw score and normalize to 0-100
  const rawTotal = fileResults.reduce((sum, f) => sum + f.fileScore, 0);
  const repoScore = Math.min(100, rawTotal);

  const hasCritical = allFindings.some(f => f.severity === 'critical');
  const hasHighOrAbove = allFindings.some(f => f.severity === 'high' || f.severity === 'critical');
  const hasMediumOrAbove = allFindings.some(f => (f.severity as Severity) !== 'low');

  let passed = repoScore < config.threshold;

  if (config.failOn === 'critical' && hasCritical) passed = false;
  if (config.failOn === 'high' && hasHighOrAbove) passed = false;
  if (config.failOn === 'medium' && hasMediumOrAbove) passed = false;

  const fileThresholdBreached = config.failFileThreshold != null &&
    fileResults.some(f => f.fileScore >= config.failFileThreshold!);

  if (fileThresholdBreached) passed = false;

  return {
    repoScore,
    scoreLabel: scoreLabel(repoScore),
    files: fileResults,
    allFindings,
    threshold: config.threshold,
    passed,
    fileThresholdBreached,
  };
}
