import fs from 'fs';
import type { ScanResult, Severity } from '../types.js';
import { escapeHtml, escapeMarkdownCell, markdownCode } from './sanitize.js';

export function buildMarkdownReport(result: ScanResult): string {
  const passed = result.passed;
  const badge = passed
    ? '![PASSED](https://img.shields.io/badge/ContextHound-PASSED-brightgreen)'
    : '![FAILED](https://img.shields.io/badge/ContextHound-FAILED-red)';

  const lines: string[] = [];

  lines.push(`# ContextHound Scan Report ${badge}`);
  lines.push('');
  lines.push(`**Score:** ${result.repoScore}/100 (${result.scoreLabel.toUpperCase()})  `);
  lines.push(`**Threshold:** ${result.threshold}  `);
  lines.push(`**Total findings:** ${result.allFindings.length}`);
  lines.push('');

  // Severity summary table
  lines.push('## Severity Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  for (const s of ['critical', 'high', 'medium', 'low'] as Severity[]) {
    const count = result.allFindings.filter(f => f.severity === s).length;
    lines.push(`| ${s} | ${count} |`);
  }
  lines.push('');

  // Per-file findings
  if (result.files.length > 0) {
    lines.push('## Findings by File');
    lines.push('');

    for (const fileResult of result.files) {
      if (fileResult.findings.length === 0) continue;
      lines.push(`### ${markdownCode(fileResult.file)}`);
      lines.push(`*File score: ${fileResult.fileScore}*`);
      lines.push('');
      lines.push('| Rule | Severity | Line | Title | MITRE |');
      lines.push('|------|----------|------|-------|-------|');
      for (const f of fileResult.findings) {
        const mitreCell = f.mitre ? `[${f.mitre}](https://attack.mitre.org/techniques/${f.mitre.replace('.', '/')})` : '';
        lines.push(`| ${escapeMarkdownCell(f.id)} | ${f.severity} | ${f.lineStart} | ${escapeMarkdownCell(f.title)} | ${mitreCell} |`);
      }
      lines.push('');

      // Remediation accordion blocks
      for (const f of fileResult.findings) {
        lines.push('<details>');
        lines.push(`<summary><strong>${escapeHtml(f.id)}</strong>: ${escapeHtml(f.title)}</summary>`);
        lines.push('');
        lines.push(`**Evidence:** ${markdownCode(f.evidence)}`);
        lines.push('');
        if (f.mitre) {
          lines.push(`**MITRE ATT&CK:** [${f.mitre}](https://attack.mitre.org/techniques/${f.mitre.replace('.', '/')})`);
          lines.push('');
        }
        lines.push(`**Remediation:** ${f.remediation}`);
        lines.push('');
        lines.push('</details>');
        lines.push('');
      }
    }
  }

  const output = lines.join('\n');

  // Write to GITHUB_STEP_SUMMARY if available
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, output + '\n', 'utf8');
  }

  return output;
}
