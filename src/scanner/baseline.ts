import fs from 'fs';
import path from 'path';
import type { AuditConfig, FileResult, Finding, ScanResult } from '../types.js';
import { buildScanResult, scoreFile } from '../scoring/index.js';

export interface BaselineOutcome {
  result: ScanResult;
  known: number;
  added: number;
  resolved: number;
}

function findingKey(f: Finding): string {
  return `${f.id}:${f.file}`;
}

/** Read the findings of a previous JSON report, or null if it cannot be loaded. */
export function loadBaseline(baselinePath: string): Finding[] | null {
  try {
    const raw = JSON.parse(fs.readFileSync(path.resolve(baselinePath), 'utf8')) as Partial<ScanResult>;
    return Array.isArray(raw.allFindings) ? raw.allFindings : [];
  } catch {
    return null;
  }
}

/**
 * Keep only findings that are not in the baseline, then rebuild the result
 * with the same scoring and gating as a normal scan so that failOn,
 * failFileThreshold and the score label all apply to the new findings.
 */
export function applyBaseline(
  result: ScanResult,
  baselineFindings: Finding[],
  config: AuditConfig,
): BaselineOutcome {
  const knownKeys = new Set(baselineFindings.map(findingKey));
  const currentKeys = new Set(result.allFindings.map(findingKey));

  const files: FileResult[] = [];
  for (const fr of result.files) {
    const findings = fr.findings.filter(f => !knownKeys.has(findingKey(f)));
    if (findings.length > 0) files.push({ file: fr.file, findings, fileScore: scoreFile(findings) });
  }

  const rebuilt = buildScanResult(files, config);
  if (result.suppressedCount !== undefined) rebuilt.suppressedCount = result.suppressedCount;
  if (result.unusedSuppressions !== undefined) rebuilt.unusedSuppressions = result.unusedSuppressions;
  if (result.skippedFiles !== undefined) rebuilt.skippedFiles = result.skippedFiles;

  return {
    result: rebuilt,
    known: baselineFindings.length,
    added: rebuilt.allFindings.length,
    resolved: baselineFindings.filter(f => !currentKeys.has(findingKey(f))).length,
  };
}
