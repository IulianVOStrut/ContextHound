import type { ScanResult, Severity } from '../types.js';
import { escapeAnnotationData, escapeAnnotationProperty } from './sanitize.js';

function severityToLevel(severity: Severity): string {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'notice';
}

export function buildGithubAnnotationsReport(result: ScanResult): string {
  const lines: string[] = [];

  for (const finding of result.allFindings) {
    const level = severityToLevel(finding.severity);
    const file = escapeAnnotationProperty(finding.file.replace(/\\/g, '/'));
    const title = escapeAnnotationProperty(finding.id);
    const message = escapeAnnotationData(`${finding.title} [${finding.severity.toUpperCase()}]`);
    lines.push(
      `::${level} file=${file},line=${finding.lineStart},endLine=${finding.lineEnd},title=${title}::${message}`
    );
  }

  return lines.join('\n');
}

/** Markdown summary table for the GitHub Actions step summary. */
export function buildStepSummary(result: ScanResult): string {
  return [
    '## ContextHound Scan Summary',
    '',
    `**Score:** ${result.repoScore}/100 (${result.scoreLabel.toUpperCase()}): ${result.passed ? '✅ PASSED' : '❌ FAILED'}`,
    '',
    '| Severity | Count |',
    '|----------|-------|',
    ...(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => {
      const count = result.allFindings.filter(f => f.severity === s).length;
      return `| ${s} | ${count} |`;
    }),
  ].join('\n');
}
