import { execFileSync } from 'child_process';
import path from 'path';

/**
 * Resolve the `--diff [ref]` option into a concrete git ref.
 * `true`/empty (flag given with no value) defaults to `origin/main`.
 * Returns null when diff mode is off.
 */
export function resolveDiffRef(diff: string | boolean | undefined): string | null {
  if (diff === undefined || diff === false) return null;
  if (diff === true || diff === '') return 'origin/main';
  return diff;
}

/**
 * Absolute paths of files that differ from `ref` — tracked changes plus
 * untracked-but-not-ignored files. Returns null if git is unavailable or the
 * ref can't be resolved (caller should fall back to a full scan).
 */
export function getChangedFiles(cwd: string, ref: string): Set<string> | null {
  try {
    const run = (args: string[]) =>
      execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const root = run(['rev-parse', '--show-toplevel']).trim();
    const tracked = run(['diff', '--name-only', ref]);
    const untracked = run(['ls-files', '--others', '--exclude-standard']);
    const rels = [...tracked.split('\n'), ...untracked.split('\n')]
      .map(s => s.trim())
      .filter(Boolean);
    return new Set(rels.map(r => path.resolve(root, r)));
  } catch {
    return null;
  }
}
