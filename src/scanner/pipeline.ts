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
import { createPathMapper, pathKey } from './paths.js';
import { assignFingerprints } from './fingerprint.js';
import type { UnusedSuppression, SkippedFile } from '../types.js';
import { DEFAULT_MAX_FILE_SIZE } from '../config/defaults.js';

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
  const discovered = await discoverFiles(cwd, config);
  let files = discovered;
  const paths = createPathMapper(cwd);

  // --diff mode: restrict to files changed vs. a git ref (fast PR gate).
  if (config.diff) {
    const changed = getChangedFiles(cwd, config.diff);
    if (changed) {
      files = files.filter(f => changed.has(pathKey(f)));
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
  const skippedFiles: SkippedFile[] = [];
  const maxFileSize = config.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  let aborted = false;

  const tasks = files.map(file =>
    limit(async () => {
      if (aborted) return;

      // One read serves both suppression parsing (always) and, on a cache
      // miss, prompt extraction. Rule execution — the expensive part — stays
      // cached; only the file read is repeated.
      let content: string;
      try {
        if (maxFileSize > 0) {
          const size = fs.statSync(file).size;
          if (size > maxFileSize) {
            skippedFiles.push({ file: paths.toReport(file), size, reason: 'max-file-size' });
            return;
          }
        }
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
            unusedSuppressions.push({ file: paths.toReport(file), line: d.declaredLine, ruleIds: d.ruleIds, reason: d.reason });
          }
        }
      }

      if (kept.length === 0) return;
      if (aborted) return; // recheck after CPU work

      // Report copies with portable paths and fingerprints. Cached findings are
      // left untouched (they stay keyed to absolute paths).
      const reportFile = paths.toReport(file);
      const reported = assignFingerprints(kept.map(f => ({ ...f, file: reportFile })));

      if (onFinding) {
        for (const f of reported) onFinding(f);
      }

      const fileScore = scoreFile(reported);
      fileResults.push({ file: reportFile, findings: reported, fileScore });

      totalFindings += reported.length;
      if (config.maxFindings && totalFindings >= config.maxFindings) {
        aborted = true;
      }
    })
  );

  await Promise.all(tasks);

  // Persist updated cache
  // Prune against every in-scope file, not just the --diff subset scanned now.
  if (useCache) saveCache(cwd, cache, discovered);

  // Sort by file path for deterministic, diffable output
  fileResults.sort((a, b) => a.file.localeCompare(b.file));

  const result = buildScanResult(fileResults, config);
  if (totalSuppressed > 0) result.suppressedCount = totalSuppressed;
  if (skippedFiles.length > 0) {
    skippedFiles.sort((a, b) => a.file.localeCompare(b.file));
    result.skippedFiles = skippedFiles;
  }
  if (config.reportUnusedSuppressions) {
    unusedSuppressions.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    result.unusedSuppressions = unusedSuppressions;
  }
  return result;
}
