import { execFileSync } from 'child_process';
import path from 'path';
import { pathKey, realpathNative } from './paths.js';

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
 * Path keys (see `pathKey`) of files changed on this branch: everything that differs
 * between the merge base of `ref` and HEAD and the working tree (committed,
 * staged and unstaged), plus untracked-but-not-ignored files. Diffing against
 * the merge base rather than `ref` itself keeps files that only changed on
 * the target branch out of a PR scan. Returns null if git is unavailable or
 * the ref can't be resolved (caller should fall back to a full scan).
 */
export function getChangedFiles(cwd: string, ref: string): Set<string> | null {
  // A ref that looks like an option would be parsed as one by git.
  if (ref.startsWith('-')) return null;
  try {
    const run = (args: string[]) =>
      execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const root = run(['rev-parse', '--show-toplevel']).trim();
    let base = ref;
    try {
      base = run(['merge-base', ref, 'HEAD']).trim() || ref;
    } catch {
      // No common ancestor (or no HEAD yet): compare against the ref itself.
    }
    // -z keeps unusual file names (spaces, quotes, non-ASCII) unquoted.
    const tracked = run(['diff', '--name-only', '-z', base, '--']);
    const untracked = run(['ls-files', '--others', '--exclude-standard', '-z']);
    const rels = [...tracked.split('\0'), ...untracked.split('\0')].filter(Boolean);
    // git reports the resolved repository root; rebase each path onto `cwd`
    // as the caller spelled it so it compares equal to discovered files.
    const rootReal = realpathNative(root);
    const cwdReal = realpathNative(cwd);
    return new Set(rels.map(r => pathKey(path.resolve(cwd, path.relative(cwdReal, path.join(rootReal, r))))));
  } catch {
    return null;
  }
}
