import type { ScanResult } from '../types.js';

function escapeXml(value: string | number): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function buildJunitReport(result: ScanResult): string {
  const lines: string[] = ['<?xml version="1.0" encoding="UTF-8"?>'];

  const totalTests = result.allFindings.length;
  const totalFailures = result.allFindings.length;

  lines.push(
    `<testsuites name="ContextHound" tests="${totalTests}" failures="${totalFailures}" errors="0" time="0">`,
  );

  // Group findings by file
  const byFile = new Map<string, typeof result.allFindings>();
  for (const f of result.allFindings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file)!.push(f);
  }

  for (const [file, findings] of byFile) {
    lines.push(
      `  <testsuite name="${escapeXml(file)}" tests="${findings.length}" failures="${findings.length}" errors="0" time="0">`,
    );

    for (const f of findings) {
      const caseName = escapeXml(`${f.id}: ${f.title}`);
      const className = escapeXml(file);
      const failureMsg = escapeXml(`${f.id} [${f.severity}]: ${f.title}`);
      const body = escapeXml(
        `File: ${f.file}\nLine: ${f.lineStart}\nEvidence: ${f.evidence}\nRemediation: ${f.remediation}`,
      );

      lines.push(`    <testcase name="${caseName}" classname="${className}" time="0">`);
      lines.push(`      <failure message="${failureMsg}" type="${escapeXml(f.severity)}">${body}</failure>`);
      lines.push(`    </testcase>`);
    }

    lines.push(`  </testsuite>`);
  }

  lines.push(`</testsuites>`);

  return lines.join('\n');
}
