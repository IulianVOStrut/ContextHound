import type { ScanResult } from '../types.js';
import { escapeCsvCell as escapeCsv } from './sanitize.js';

export function buildCsvReport(result: ScanResult): string {
  const headers = [
    'rule_id', 'severity', 'confidence',
    'file', 'line_start', 'line_end',
    'title', 'evidence', 'remediation', 'mitre_technique',
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
      escapeCsv(f.mitre ?? ''),
    ].join(','));
  }

  return rows.join('\n');
}
