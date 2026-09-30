import type { Finding, ScanResult, Severity } from '../types.js';
import { markdownCode } from './sanitize.js';

/** Hidden marker that identifies the ContextHound comment on a pull request. */
export const PR_COMMENT_MARKER = '<!-- contexthound-pr-comment -->';

// GitHub rejects comment bodies over 65,536 characters.
const MAX_BODY = 60_000;

export interface PrCommentOptions {
  /** Base URL for file links, e.g. https://github.com/o/r/blob/<sha>. */
  blobBaseUrl?: string;
  /** Git ref the scan was limited to with --diff, if any. */
  diffRef?: string;
  /** Maximum number of findings listed in the table (default 50). */
  maxRows?: number;
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/** A code span that is also safe inside a GFM table cell. Code spans stop @mentions and HTML. */
function cellCode(value: string): string {
  return markdownCode(value).replace(/\|/g, '\\|');
}

function fileUrl(base: string, file: string, line: number): string {
  const encoded = file.split('/').map(encodeURIComponent).join('/');
  return `${base.replace(/\/+$/, '')}/${encoded}#L${line}`;
}

function location(f: Finding, base?: string): string {
  const text = cellCode(`${f.file}:${f.lineStart}`);
  return base ? `[${text}](${fileUrl(base, f.file, f.lineStart)})` : text;
}

/**
 * A compact Markdown summary for a pull request comment. Every value that
 * comes from scanned files (paths, evidence) is rendered as a code span, so a
 * malicious pull request cannot inject Markdown, HTML, links or @mentions.
 */
export function buildPrComment(result: ScanResult, options: PrCommentOptions = {}): string {
  const maxRows = options.maxRows ?? 50;
  const findings = [...result.allFindings].sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.file.localeCompare(b.file) || a.lineStart - b.lineStart);

  const lines: string[] = [PR_COMMENT_MARKER];
  const status = result.passed ? 'Passed' : 'Failed';
  lines.push(`### ContextHound: ${status}`);
  lines.push('');
  const scope = options.diffRef ? ` in files changed since ${cellCode(options.diffRef)}` : '';
  lines.push(`Risk score **${result.repoScore}/100** (${result.scoreLabel}), threshold ${result.threshold}. ` +
    `${findings.length} finding${findings.length === 1 ? '' : 's'}${scope}.`);
  // Failure messages can quote a scanned file path, so they are code too.
  for (const failure of result.failures ?? []) lines.push(`- ${markdownCode(failure.message)}`);
  lines.push('');

  if (findings.length === 0) {
    lines.push('No findings.');
    return lines.join('\n');
  }

  lines.push(SEVERITIES.map(s => `${s}: ${findings.filter(f => f.severity === s).length}`).join(' · '));
  lines.push('');
  lines.push('| Severity | Rule | Location | Issue |');
  lines.push('|---|---|---|---|');
  const rows = findings.slice(0, maxRows);
  for (const f of rows) {
    lines.push(`| ${f.severity} | ${cellCode(f.id)} | ${location(f, options.blobBaseUrl)} | ${cellCode(f.title)} |`);
  }
  if (findings.length > rows.length) {
    lines.push('');
    lines.push(`${findings.length - rows.length} more finding(s) not shown. See the Code Scanning alerts or the SARIF report.`);
  }
  lines.push('');
  lines.push('<details><summary>Evidence</summary>');
  lines.push('');
  for (const f of rows) lines.push(`- ${cellCode(f.id)} ${cellCode(`${f.file}:${f.lineStart}`)}: ${markdownCode(f.evidence)}`);
  lines.push('');
  lines.push('</details>');
  lines.push('');
  lines.push('Run `hound explain <RULE-ID>` for remediation. Suppress a reviewed finding with `// hound-disable-next-line <RULE-ID> -- reason`.');

  let body = lines.join('\n');
  if (body.length > MAX_BODY) {
    body = `${body.slice(0, MAX_BODY)}\n\n_Truncated: the full list is in the SARIF report._`;
  }
  return body;
}
