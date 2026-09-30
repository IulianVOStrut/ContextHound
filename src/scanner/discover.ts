import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import fg from 'fast-glob';
import ignore from 'ignore';
import type { AuditConfig } from '../types.js';

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

function readIgnoreFile(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Files matched by `.houndignore` in the scan directory (gitignore syntax). */
function houndIgnored(cwd: string, rels: string[]): Set<string> {
  const text = readIgnoreFile(path.join(cwd, '.houndignore'));
  if (!text) return new Set();
  const ig = ignore().add(text);
  return new Set(rels.filter(r => ig.ignores(r)));
}

/**
 * Files git would ignore. Inside a repository this asks git itself, which
 * covers nested .gitignore files, .git/info/exclude and the global excludes
 * file, and never reports tracked files. Outside git, the scan directory's
 * own .gitignore is applied.
 */
function gitIgnored(cwd: string, rels: string[]): Set<string> {
  if (rels.length === 0) return new Set();
  const res = spawnSync('git', ['check-ignore', '--stdin', '-z'], {
    cwd,
    input: rels.join('\0'),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  // Exit 0: some paths ignored. Exit 1: none ignored. Anything else (128 for
  // "not a git repository", or git missing): fall back to .gitignore.
  if (!res.error && (res.status === 0 || res.status === 1)) {
    return new Set(res.stdout.split('\0').filter(Boolean));
  }
  const text = readIgnoreFile(path.join(cwd, '.gitignore'));
  if (!text) return new Set();
  const ig = ignore().add(text);
  return new Set(rels.filter(r => ig.ignores(r)));
}

/**
 * Absolute paths of the files to scan: `include` minus `exclude`, minus
 * anything matched by `.houndignore` and, unless `config.gitignore` is false,
 * anything git ignores.
 */
export async function discoverFiles(cwd: string, config: AuditConfig): Promise<string[]> {
  const root = path.resolve(cwd);
  const files = await fg(config.include, {
    cwd: root,
    ignore: config.exclude,
    absolute: true,
    followSymbolicLinks: false,
    onlyFiles: true,
  });

  const rels = files.map(f => toPosix(path.relative(root, f)));
  const skip = houndIgnored(root, rels);
  if (config.gitignore !== false) {
    for (const r of gitIgnored(root, rels.filter(r => !skip.has(r)))) skip.add(r);
  }
  return files.filter((_, i) => !skip.has(rels[i])).sort();
}
