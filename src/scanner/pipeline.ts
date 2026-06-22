import fs from 'fs';
import path from 'path';
import type { AuditConfig, FileResult, Finding, ScanResult } from '../types.js';
import type { Rule } from '../rules/index.js';
import { discoverFiles } from './discover.js';
import { extractPrompts } from './extractor.js';
import { analyzePrompt, scoreFile, buildScanResult } from '../scoring/index.js';
import { allRules } from '../rules/index.js';
import { loadCache, saveCache, getCachedFindings, setCacheEntry, computeCacheSignature } from './cache.js';
import type { HoundCache } from './cache.js';
import { parseSuppressions, applySuppressions } from './suppressions.js';
import { getChangedFiles } from './gitDiff.js';
import type { UnusedSuppression } from '../types.js';

async function loadHoundIgnore(cwd: string): Promise<string[]> {
  const p = path.join(cwd, '.houndignore');
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

// Inline concurrency limiter — avoids p-limit (ESM-only, incompatible with CommonJS)
function createLimiter(concurrency: number) {
  let active = 0;
  const queue: Array<() => void> = [];

  function next() {
    while (queue.length > 0 && active < concurrency) {
      active++;
      queue.shift()!();
    }
  }

  return function limit<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      queue.push(() => {
        fn().then(resolve, reject).finally(() => {
          active--;
          next();
        });
      });
      next();
    });
  };
}

async function loadPluginRules(plugins: string[], cwd: string): Promise<Rule[]> {
  const rules: Rule[] = [];
  for (const pluginPath of plugins) {
    const resolved = path.isAbsolute(pluginPath)
      ? pluginPath
      : path.join(cwd, pluginPath);
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const mod = require(resolved) as Rule | Rule[] | { default: Rule | Rule[] };
      const exported = 'default' in mod ? (mod as { default: Rule | Rule[] }).default : mod;
      if (Array.isArray(exported)) {
        rules.push(...(exported as Rule[]));
      } else if (exported && typeof exported === 'object' && 'check' in exported) {
        rules.push(exported as Rule);
      } else {
        console.warn(`Warning: plugin ${pluginPath} did not export a Rule or Rule[]`);
      }
    } catch (err) {
      console.warn(`Warning: failed to load plugin ${pluginPath}: ${(err as Error).message}`);
    }
  }
  return rules;
}

export async function runScan(
  cwd: string,
  config: AuditConfig,
  onFinding?: (finding: Finding) => void
): Promise<ScanResult> {
  // Merge .houndignore patterns into exclude list
  const houndIgnorePatterns = await loadHoundIgnore(cwd);
  if (houndIgnorePatterns.length > 0) {
    config = { ...config, exclude: [...config.exclude, ...houndIgnorePatterns] };
  }

  let files = await discoverFiles(cwd, config);

  // --diff mode: restrict to files changed vs. a git ref (fast PR gate).
  if (config.diff) {
    const changed = getChangedFiles(cwd, config.diff);
    if (changed) {
      files = files.filter(f => changed.has(f));
    } else {
      console.warn(`Warning: could not compute git diff against '${config.diff}'; scanning all files`);
    }
  }

  // Load plugin rules
  const pluginRules = config.plugins?.length
    ? await loadPluginRules(config.plugins, cwd)
    : undefined;

  // Load cache (enabled by default; disabled with cache: false). The signature
  // ties the cache to the effective ruleset + findings-affecting config, so a
  // rules upgrade or filter change discards stale entries instead of serving them.
  const useCache = config.cache !== false;
  const cacheSignature = computeCacheSignature(
    pluginRules ? [...allRules, ...pluginRules] : allRules,
    config,
  );
  const cache: HoundCache = useCache
    ? loadCache(cwd, cacheSignature)
    : { version: cacheSignature, entries: {} };

  const concurrency = config.concurrency ?? 8;
  const limit = createLimiter(concurrency);

  const fileResults: FileResult[] = [];
  let totalFindings = 0;
  let totalSuppressed = 0;
  const unusedSuppressions: UnusedSuppression[] = [];
  let aborted = false;

  const tasks = files.map(file =>
    limit(async () => {
      if (aborted) return;

      // One read serves both suppression parsing (always) and, on a cache
      // miss, prompt extraction. Rule execution — the expensive part — stays
      // cached; only the file read is repeated.
      let content: string;
      try {
        content = fs.readFileSync(file, 'utf8');
      } catch {
        return;
      }

      // Raw (pre-suppression) findings, from cache when the file is unchanged.
      let rawFindings: Finding[] | null = useCache ? getCachedFindings(cache, file) : null;
      if (rawFindings === null) {
        const prompts = extractPrompts(file, content);
        rawFindings = prompts.length === 0 ? [] : analyzePrompt(prompts, file, config, pluginRules);
        if (useCache) setCacheEntry(cache, file, rawFindings);
      }

      // Apply inline suppression directives (hound-disable-*).
      const directives = parseSuppressions(content);
      const { kept, suppressedCount } = applySuppressions(rawFindings, directives);
      totalSuppressed += suppressedCount;
      if (config.reportUnusedSuppressions) {
        for (const d of directives) {
          if (!d.used) {
            unusedSuppressions.push({ file, line: d.declaredLine, ruleIds: d.ruleIds, reason: d.reason });
          }
        }
      }

      if (kept.length === 0) return;
      if (aborted) return; // recheck after CPU work

      if (onFinding) {
        for (const f of kept) onFinding(f);
      }

      const fileScore = scoreFile(kept);
      fileResults.push({ file, findings: kept, fileScore });

      totalFindings += kept.length;
      if (config.maxFindings && totalFindings >= config.maxFindings) {
        aborted = true;
      }
    })
  );

  await Promise.all(tasks);

  // Persist updated cache
  if (useCache) saveCache(cwd, cache);

  // Sort by file path for deterministic, diffable output
  fileResults.sort((a, b) => a.file.localeCompare(b.file));

  const result = buildScanResult(fileResults, config);
  if (totalSuppressed > 0) result.suppressedCount = totalSuppressed;
  if (config.reportUnusedSuppressions) {
    unusedSuppressions.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    result.unusedSuppressions = unusedSuppressions;
  }
  return result;
}
