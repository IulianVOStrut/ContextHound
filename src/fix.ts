import fs from 'fs';
import path from 'path';
import type { AuditConfig } from './types.js';
import { allRules } from './rules/index.js';
import type { Rule } from './rules/types.js';
import { runScan } from './scanner/pipeline.js';
import { createPathMapper } from './scanner/paths.js';

export interface LineChange {
  line: number;
  before: string;
  after: string;
  ruleIds: string[];
}

export interface FileFix {
  /** Report path, relative to the repository root. */
  file: string;
  /** Absolute path on disk. */
  absolutePath: string;
  changes: LineChange[];
}

/** Built-in rules that have a safe automatic fix. */
export function fixableRules(rules: readonly Rule[] = allRules): Rule[] {
  return rules.filter(r => typeof r.fix === 'function');
}

/**
 * Scan and work out the safe fixes for the findings, without writing
 * anything. Suppressed findings are left alone. Only rules with a `fix`
 * function contribute, and a line is only changed if the fix changes it.
 */
export async function computeFixes(cwd: string, config: AuditConfig): Promise<FileFix[]> {
  const byId = new Map(fixableRules().map(r => [r.id, r]));
  if (byId.size === 0) return [];
  const result = await runScan(cwd, { ...config, cache: false });
  const root = createPathMapper(cwd).root;

  const fixes: FileFix[] = [];
  for (const fr of result.files) {
    const lineRules = new Map<number, Rule[]>();
    for (const f of fr.findings) {
      const rule = byId.get(f.id);
      if (!rule) continue;
      for (let n = f.lineStart; n <= f.lineEnd; n++) {
        const list = lineRules.get(n) ?? [];
        if (!list.includes(rule)) list.push(rule);
        lineRules.set(n, list);
      }
    }
    if (lineRules.size === 0) continue;

    const absolutePath = path.join(root, fr.file);
    const lines = fs.readFileSync(absolutePath, 'utf8').split('\n');
    const changes: LineChange[] = [];
    for (const [n, rules] of [...lineRules].sort((a, b) => a[0] - b[0])) {
      const before = lines[n - 1];
      if (before === undefined) continue;
      const after = rules.reduce((text, rule) => (rule.fix as (l: string) => string)(text), before);
      if (after !== before) changes.push({ line: n, before, after, ruleIds: rules.map(r => r.id) });
    }
    if (changes.length > 0) fixes.push({ file: fr.file, absolutePath, changes });
  }
  return fixes;
}

/** Write the fixes to disk. Lines are replaced by number, so each file is re-read first. */
export function applyFixes(fixes: FileFix[]): void {
  for (const fix of fixes) {
    const lines = fs.readFileSync(fix.absolutePath, 'utf8').split('\n');
    for (const change of fix.changes) {
      if (lines[change.line - 1] === change.before) lines[change.line - 1] = change.after;
    }
    fs.writeFileSync(fix.absolutePath, lines.join('\n'), 'utf8');
  }
}
