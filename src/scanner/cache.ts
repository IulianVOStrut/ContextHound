import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import type { AuditConfig, Finding } from '../types.js';
import type { Rule } from '../rules/types.js';

// Bump when the cache file layout changes. Combined with the ruleset/config
// hash below to form the stored `version`, so old-format caches are discarded.
const CACHE_FORMAT_VERSION = '2';
const CACHE_FILENAME = '.hound-cache.json';

interface CacheEntry {
  mtime: number;
  findings: Finding[];
}

export interface HoundCache {
  version: string;
  entries: Record<string, CacheEntry>;
}

// A cache entry is only valid if the ruleset and the findings-affecting config
// that produced it are unchanged. We fold both into the stored `version` so a
// rules upgrade (or a `--include-rules`/`--min-confidence` change) automatically
// invalidates stale findings rather than silently serving them from mtime alone.
export function computeCacheSignature(
  rules: Rule[],
  config: Pick<AuditConfig, 'includeRules' | 'excludeRules' | 'minConfidence'>,
): string {
  const hash = crypto.createHash('sha256');
  hash.update(`format:${CACHE_FORMAT_VERSION} rules `);
  // Sort by id so registration order doesn't change the signature.
  const sorted = [...rules].sort((a, b) => a.id.localeCompare(b.id));
  for (const r of sorted) {
    hash.update(`${r.id}|${r.severity}|${r.confidence}|${r.category}|${r.mitre ?? ''}|`);
    // Hashing the check source captures rule-logic changes within a version,
    // including local edits and plugin rules.
    hash.update(r.check.toString());
    hash.update(' ');
  }
  hash.update('config ');
  hash.update(`inc:${[...(config.includeRules ?? [])].sort().join(',')} `);
  hash.update(`exc:${[...(config.excludeRules ?? [])].sort().join(',')} `);
  hash.update(`minc:${config.minConfidence ?? ''}`);
  return `${CACHE_FORMAT_VERSION}-${hash.digest('hex').slice(0, 16)}`;
}

export function loadCache(cwd: string, signature: string): HoundCache {
  const cachePath = path.join(cwd, CACHE_FILENAME);
  if (!fs.existsSync(cachePath)) {
    return { version: signature, entries: {} };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(cachePath, 'utf8')) as HoundCache;
    if (raw.version !== signature) {
      return { version: signature, entries: {} };
    }
    return raw;
  } catch {
    return { version: signature, entries: {} };
  }
}

export function saveCache(cwd: string, cache: HoundCache): void {
  const cachePath = path.join(cwd, CACHE_FILENAME);
  try {
    fs.writeFileSync(cachePath, JSON.stringify(cache, null, 2), 'utf8');
  } catch {
    // Cache write failures are non-fatal
  }
}

export function getCachedFindings(cache: HoundCache, filePath: string): Finding[] | null {
  const entry = cache.entries[filePath];
  if (!entry) return null;
  try {
    const mtime = fs.statSync(filePath).mtimeMs;
    if (mtime === entry.mtime) return entry.findings;
  } catch {
    // File may have been deleted; treat as cache miss
  }
  return null;
}

export function setCacheEntry(cache: HoundCache, filePath: string, findings: Finding[]): void {
  try {
    const mtime = fs.statSync(filePath).mtimeMs;
    cache.entries[filePath] = { mtime, findings };
  } catch {
    // If stat fails, skip caching this file
  }
}
