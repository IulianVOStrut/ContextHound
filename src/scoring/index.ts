import type { Finding, FileResult, ScanResult, ScanFailure, Severity, AuditConfig, Confidence } from '../types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';
import { allRules, ruleToFinding, scoreMitigations, mitigationReductionFor } from '../rules/index.js';
import type { Rule } from '../rules/index.js';

const SEVERITIES_AT_OR_ABOVE: Record<NonNullable<AuditConfig['failOn']>, Severity[]> = {
  critical: ['critical'],
  high: ['critical', 'high'],
  medium: ['critical', 'high', 'medium'],
};

export function scoreLabel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score < 30) return 'low';
  if (score < 60) return 'medium';
  if (score < 80) return 'high';
  return 'critical';
}

const reportedRuleErrors = new Set<string>();

function reportRuleError(ruleId: string, filePath: string, err: unknown): void {
  if (reportedRuleErrors.has(ruleId)) return;
  reportedRuleErrors.add(ruleId);
  const msg = err instanceof Error ? err.message : String(err);
  console.warn(`Warning: rule ${ruleId} failed on ${filePath} and was skipped: ${msg}`);
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
  const pluginRules = new Set<Rule>(extraRules ?? []);

  for (const prompt of prompts) {
    // Get mitigations for this prompt
    const mitigation = scoreMitigations(prompt);

    for (const rule of ruleset) {
      // General documentation only gets rules that are meaningful in any text.
      // Plugin rules predate the flag, so they keep running everywhere unless
      // they opt out with `docs: false`.
      if (prompt.context === 'doc' && !(rule.docs ?? pluginRules.has(rule))) continue;
      // Apply rule filters
      if (config?.excludeRules?.some(p => matchesFilter(rule.id, p))) continue;
      if (config?.includeRules?.length &&
          !config.includeRules.some(p => matchesFilter(rule.id, p))) continue;
      if (config?.minConfidence) {
        if (confidenceOrder.indexOf(rule.confidence) < confidenceOrder.indexOf(config.minConfidence)) continue;
      }

      let matches: ReturnType<Rule['check']>;
      try {
        matches = rule.check(prompt, filePath);
      } catch (err) {
        // A rule must never take the whole scan down: scanned content is
        // untrusted and plugin rules are third-party code.
        reportRuleError(rule.id, filePath, err);
        continue;
      }
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

// ── Scores ────────────────────────────────────────────────────────────────────
//
// Risk points (severity weight x confidence, reduced by relevant mitigations)
// are combined probabilistically instead of summed, so scores approach 100
// only as risk accumulates and do not saturate after two findings:
//
//   combine(p1..pn) = 100 x (1 - (1 - p1/100) x ... x (1 - pn/100))
//
// File score: each rule counts once per file (its highest points), so one
// rule repeating 50 times in a data file does not drown everything else.
// Repo score: files are sorted worst first and each subsequent file counts
// half as much as the previous one, so the score reflects how bad the worst
// problems are rather than how large the repository is.

/** Combine independent risk points (0-100 each) into one 0-100 score. */
export function combineRisk(points: number[]): number {
  let clean = 1;
  for (const p of points) clean *= 1 - Math.min(100, Math.max(0, p)) / 100;
  return Math.round(100 * (1 - clean));
}

export function scoreFile(findings: Finding[]): number {
  const perRule = new Map<string, number>();
  for (const f of findings) perRule.set(f.id, Math.max(perRule.get(f.id) ?? 0, f.riskPoints));
  return combineRisk([...perRule.values()]);
}

export function scoreRepo(fileScores: number[]): number {
  const sorted = [...fileScores].sort((a, b) => b - a);
  return combineRisk(sorted.map((score, i) => score / 2 ** i));
}

export function buildScanResult(
  fileResults: FileResult[],
  config: AuditConfig
): ScanResult {
  const allFindings = fileResults.flatMap(f => f.findings);

  const repoScore = scoreRepo(fileResults.map(f => f.fileScore));

  const failures: ScanFailure[] = [];

  if (repoScore >= config.threshold) {
    failures.push({ kind: 'threshold', message: `repo score ${repoScore} is at or above the threshold of ${config.threshold}` });
  }

  if (config.failOn) {
    const gated = new Set<Severity>(SEVERITIES_AT_OR_ABOVE[config.failOn]);
    const count = allFindings.filter(f => gated.has(f.severity)).length;
    if (count > 0) {
      failures.push({ kind: 'fail-on', message: `${count} finding(s) at ${config.failOn} severity or above (fail-on: ${config.failOn})` });
    }
  }

  const overFileThreshold = config.failFileThreshold != null
    ? fileResults.filter(f => f.fileScore >= config.failFileThreshold!)
    : [];
  const fileThresholdBreached = overFileThreshold.length > 0;
  if (fileThresholdBreached) {
    const worst = overFileThreshold.reduce((a, b) => (b.fileScore > a.fileScore ? b : a));
    failures.push({
      kind: 'file-threshold',
      message: `${overFileThreshold.length} file(s) at or above the file threshold of ${config.failFileThreshold} (highest: ${worst.file} with ${worst.fileScore})`,
    });
  }

  return {
    repoScore,
    scoreLabel: scoreLabel(repoScore),
    files: fileResults,
    allFindings,
    threshold: config.threshold,
    passed: failures.length === 0,
    fileThresholdBreached,
    ...(failures.length > 0 && { failures }),
  };
}
