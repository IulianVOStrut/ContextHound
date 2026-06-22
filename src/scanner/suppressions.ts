import fs from 'fs';
import type { Finding } from '../types.js';

// ── Inline suppression directives ─────────────────────────────────────────────
//
// ContextHound honours comment-based suppression directives, in the spirit of
// `eslint-disable` / `# nosec`. They work in any file type because they are
// matched anywhere on a line, regardless of the surrounding comment syntax.
//
//   hound-disable-line [RULE...] [-- reason]      suppress findings on this line
//   hound-disable-next-line [RULE...] [-- reason] suppress findings on the next line
//   hound-disable [RULE...] [-- reason]           open a block suppression
//   hound-enable [RULE...]                         close a block suppression
//
// When no rule IDs are listed, the directive suppresses *all* rules at that
// location. A block left open is implicitly closed at end of file.

export interface SuppressionDirective {
  type: 'line' | 'next-line' | 'block';
  /** 1-based source line the directive comment appears on. */
  declaredLine: number;
  /** Inclusive 1-based source line range this directive covers. */
  startLine: number;
  endLine: number;
  /** Targeted rule IDs, or null to suppress every rule. */
  ruleIds: string[] | null;
  reason?: string;
  /** Set when at least one finding was actually suppressed by this directive. */
  used: boolean;
}

const DIRECTIVE_RE = /hound-(disable-next-line|disable-line|disable|enable)\b([^\n]*)/i;
const RULE_ID_RE = /[A-Za-z][A-Za-z0-9]*-\d+/g;

function parseTail(tail: string): { ruleIds: string[] | null; reason?: string } {
  // A `--` separates the optional human-readable reason from the rule list.
  const sepIdx = tail.indexOf('--');
  const idsPart = sepIdx === -1 ? tail : tail.slice(0, sepIdx);
  const reasonRaw = sepIdx === -1 ? '' : tail.slice(sepIdx + 2).trim();
  const ids = idsPart.match(RULE_ID_RE)?.map(s => s.toUpperCase()) ?? [];
  return {
    ruleIds: ids.length > 0 ? ids : null,
    reason: reasonRaw.length > 0 ? reasonRaw : undefined,
  };
}

/** Parse all suppression directives from raw file content. */
export function parseSuppressions(content: string): SuppressionDirective[] {
  const lines = content.split('\n');
  const directives: SuppressionDirective[] = [];
  const openBlocks: SuppressionDirective[] = [];

  lines.forEach((line, idx) => {
    const m = DIRECTIVE_RE.exec(line);
    if (!m) return;
    const lineNo = idx + 1;
    const kind = m[1].toLowerCase();
    const { ruleIds, reason } = parseTail(m[2]);

    if (kind === 'disable-line') {
      directives.push({ type: 'line', declaredLine: lineNo, startLine: lineNo, endLine: lineNo, ruleIds, reason, used: false });
    } else if (kind === 'disable-next-line') {
      directives.push({ type: 'next-line', declaredLine: lineNo, startLine: lineNo + 1, endLine: lineNo + 1, ruleIds, reason, used: false });
    } else if (kind === 'disable') {
      const d: SuppressionDirective = { type: 'block', declaredLine: lineNo, startLine: lineNo, endLine: lines.length, ruleIds, reason, used: false };
      directives.push(d);
      openBlocks.push(d);
    } else { // enable
      for (let k = openBlocks.length - 1; k >= 0; k--) {
        const b = openBlocks[k];
        const matches = ruleIds === null || b.ruleIds === null || ruleIds.some(id => b.ruleIds!.includes(id));
        if (matches) {
          b.endLine = lineNo;
          openBlocks.splice(k, 1);
        }
      }
    }
  });

  return directives;
}

function findSuppressor(
  directives: SuppressionDirective[],
  line: number,
  ruleId: string,
): SuppressionDirective | null {
  for (const d of directives) {
    if (line >= d.startLine && line <= d.endLine && (d.ruleIds === null || d.ruleIds.includes(ruleId))) {
      return d;
    }
  }
  return null;
}

export interface SuppressionResult {
  kept: Finding[];
  suppressedCount: number;
}

/**
 * Split findings into those that survive suppression and those silenced by a
 * directive. Mutates `directives` to flag which ones were actually used.
 */
export function applySuppressions(
  findings: Finding[],
  directives: SuppressionDirective[],
): SuppressionResult {
  if (directives.length === 0) return { kept: findings, suppressedCount: 0 };

  const kept: Finding[] = [];
  let suppressedCount = 0;
  for (const f of findings) {
    const d = findSuppressor(directives, f.lineStart, f.id);
    if (d) {
      d.used = true;
      suppressedCount++;
    } else {
      kept.push(f);
    }
  }
  return { kept, suppressedCount };
}

/** Read a file and parse its suppression directives; empty on read failure. */
export function parseSuppressionsFromFile(filePath: string): SuppressionDirective[] {
  try {
    return parseSuppressions(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return [];
  }
}
