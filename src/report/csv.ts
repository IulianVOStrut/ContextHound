import type { ScanResult } from '../types.js';

function escapeCsv(value: string | number): string {
  const s = String(value);
  // Wrap in double-quotes if the value contains a comma, double-quote, or newline
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function buildCsvReport(result: ScanResult): string {
  const headers = [
    'rule_id', 'severity', 'confidence',
    'file', 'line_start', 'line_end',
    'title', 'evidence', 'remediation',
  ];

  const rows: string[] = [headers.join(',')];

  for (const f of result.allFindings) {
    rows.push([
      escapeCsv(f.id),
      escapeCsv(f.severity),
      escapeCsv(f.confidence),
      escapeCsv(f.file),
      escapeCsv(f.lineStart),
      escapeCsv(f.lineEnd),
      escapeCsv(f.title),
      escapeCsv(f.evidence),
      escapeCsv(f.remediation),
    ].join(','));
  }

  return rows.join('\n');
}
