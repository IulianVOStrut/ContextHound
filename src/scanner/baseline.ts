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

function legacyKey(id: string, file: string): string {
  return `${id}:${file}`;
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
 *
 * Findings match on their fingerprint (rule, path, evidence, occurrence), so a
 * second instance of a rule in a known file is still reported. Baselines
 * written before fingerprints existed fall back to rule + file, and their
 * absolute paths are mapped with `toReportPath` when given.
 */
export function applyBaseline(
  result: ScanResult,
  baselineFindings: Finding[],
  config: AuditConfig,
  toReportPath: (file: string) => string = f => f,
): BaselineOutcome {
  const legacyPath = (file: string) => (path.isAbsolute(file) ? toReportPath(file) : file);
  const knownFingerprints = new Set<string>();
  const knownLegacy = new Set<string>();
  for (const b of baselineFindings) {
    if (b.fingerprint) knownFingerprints.add(b.fingerprint);
    else knownLegacy.add(legacyKey(b.id, legacyPath(b.file)));
  }
  const isKnown = (f: Finding) =>
    (f.fingerprint !== undefined && knownFingerprints.has(f.fingerprint)) || knownLegacy.has(legacyKey(f.id, f.file));

  const currentFingerprints = new Set(result.allFindings.map(f => f.fingerprint).filter((x): x is string => !!x));
  const currentLegacy = new Set(result.allFindings.map(f => legacyKey(f.id, f.file)));
  const stillPresent = (b: Finding) =>
    b.fingerprint ? currentFingerprints.has(b.fingerprint) : currentLegacy.has(legacyKey(b.id, legacyPath(b.file)));

  const files: FileResult[] = [];
  for (const fr of result.files) {
    const findings = fr.findings.filter(f => !isKnown(f));
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
    resolved: baselineFindings.filter(b => !stillPresent(b)).length,
  };
}
