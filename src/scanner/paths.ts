import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

// Report paths are POSIX paths relative to the git repository root that
// contains the scan directory, or to the scan directory itself outside git.
// That is what GitHub Code Scanning and annotations expect (even with
// --dir sub), it keeps machine-specific absolute paths out of shared reports,
// and it lets a baseline made on one machine match on another.

export interface PathMapper {
  /** Absolute path of the directory report paths are relative to. */
  root: string;
  /** Map an absolute file path to its report path. */
  toReport(absolutePath: string): string;
}

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

function gitToplevel(dir: string): string | null {
  try {
    return execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || null;
  } catch {
    return null;
  }
}

/**
 * Resolve symlinks and, on Windows, 8.3 short names such as PROGRA~1, which
 * git never reports. Falls back to the input when the path does not exist.
 */
export function realpathNative(p: string): string {
  try { return fs.realpathSync.native(p); } catch { return p; }
}

/**
 * Key for comparing file paths from different sources (fast-glob returns
 * forward slashes on Windows, path.resolve returns backslashes, and Windows
 * paths are case-insensitive).
 */
export function pathKey(p: string): string {
  const resolved = path.resolve(p);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

export function createPathMapper(scanDir: string): PathMapper {
  const scanAbs = path.resolve(scanDir);
  // Location of the scan dir inside the repo, e.g. "packages/api". Computed on
  // real paths because git reports the resolved toplevel (symlinks followed).
  let prefix = '';
  let root = scanAbs;
  const top = gitToplevel(scanAbs);
  if (top) {
    const rel = path.relative(realpathNative(top), realpathNative(scanAbs));
    if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
      prefix = rel;
      root = top;
    }
  }
  return {
    root,
    toReport(absolutePath: string): string {
      const rel = path.relative(scanAbs, absolutePath);
      return toPosix(prefix ? path.join(prefix, rel) : rel) || '.';
    },
  };
}
