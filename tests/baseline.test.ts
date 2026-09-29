import { applyBaseline, loadBaseline } from '../src/scanner/baseline';
import { buildScanResult, scoreFile } from '../src/scoring/index';
import { DEFAULT_CONFIG } from '../src/config/defaults';
import type { AuditConfig, FileResult, Finding } from '../src/types';

function finding(id: string, file: string, severity: Finding['severity'], riskPoints: number): Finding {
  return {
    id, title: id, severity, confidence: 'high', evidence: 'e', file,
    lineStart: 1, lineEnd: 1, remediation: '-', riskPoints,
  };
}

function scan(findings: Finding[], config: AuditConfig) {
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
  const files: FileResult[] = [...byFile].map(([file, fs]) => ({ file, findings: fs, fileScore: scoreFile(fs) }));
  return buildScanResult(files, config);
}

const oldHigh = finding('INJ-001', 'a.ts', 'high', 30);
const newCritical = finding('JBK-001', 'b.prompt', 'critical', 50);

describe('applyBaseline', () => {
  it('enforces failOn against new findings even when the score is under threshold', () => {
    const config = { ...DEFAULT_CONFIG, threshold: 100, failOn: 'critical' as const };
    const { result, added, known, resolved } = applyBaseline(scan([oldHigh, newCritical], config), [oldHigh], config);
    expect(result.allFindings.map(f => f.id)).toEqual(['JBK-001']);
    expect(result.passed).toBe(false);
    expect({ known, added, resolved }).toEqual({ known: 1, added: 1, resolved: 0 });
  });

  it('passes when every finding is already in the baseline', () => {
    const config = { ...DEFAULT_CONFIG, threshold: 1, failOn: 'critical' as const };
    const { result } = applyBaseline(scan([oldHigh, newCritical], config), [oldHigh, newCritical], config);
    expect(result.allFindings).toHaveLength(0);
    expect(result.repoScore).toBe(0);
    expect(result.passed).toBe(true);
  });

  it('enforces failFileThreshold using only new findings in each file', () => {
    const config = { ...DEFAULT_CONFIG, threshold: 100, failFileThreshold: 40 };
    const knownInB = finding('EXF-001', 'b.prompt', 'critical', 50);
    const { result } = applyBaseline(scan([knownInB, newCritical], config), [knownInB], config);
    expect(result.files[0].fileScore).toBe(50);
    expect(result.fileThresholdBreached).toBe(true);
    expect(result.passed).toBe(false);
  });

  it('recomputes file scores so known findings no longer count', () => {
    const config = { ...DEFAULT_CONFIG, threshold: 60 };
    const knownInB = finding('EXF-001', 'b.prompt', 'critical', 50);
    const { result } = applyBaseline(scan([knownInB, newCritical], config), [knownInB], config);
    expect(result.files[0].fileScore).toBe(50);
    expect(result.repoScore).toBe(50);
  });

  it('derives the score label from the new score, not the pre-baseline score', () => {
    const config = { ...DEFAULT_CONFIG, threshold: 100 };
    const many = [oldHigh, finding('INJ-002', 'a.ts', 'critical', 50), finding('INJ-003', 'a.ts', 'critical', 50)];
    const before = scan([...many, finding('INJ-004', 'c.ts', 'low', 5)], config);
    expect(before.scoreLabel).toBe('critical');
    const { result } = applyBaseline(before, many, config);
    expect(result.repoScore).toBe(5);
    expect(result.scoreLabel).toBe('low');
  });

  it('keeps suppression and skipped-file metadata', () => {
    const config = { ...DEFAULT_CONFIG };
    const base = scan([oldHigh], config);
    base.suppressedCount = 2;
    base.skippedFiles = [{ file: 'big.json', size: 9, reason: 'max-file-size' }];
    const { result } = applyBaseline(base, [], config);
    expect(result.suppressedCount).toBe(2);
    expect(result.skippedFiles).toHaveLength(1);
  });
});

describe('loadBaseline', () => {
  it('returns null for a missing or unparseable file', () => {
    expect(loadBaseline('/nonexistent/baseline.json')).toBeNull();
  });
});
