import { scoreFile, buildScanResult, scoreLabel } from '../src/scoring/index';
import type { Finding, FileResult } from '../src/types';
import { DEFAULT_CONFIG } from '../src/config/defaults';

const makeFinding = (severity: Finding['severity'], confidence: Finding['confidence'], riskPoints: number): Finding => ({
  id: 'TEST-001',
  title: 'Test finding',
  severity,
  confidence,
  evidence: 'test evidence',
  file: 'test.ts',
  lineStart: 1,
  lineEnd: 1,
  remediation: 'Fix it',
  riskPoints,
});

describe('scoreLabel', () => {
  it('returns low for 0-29', () => {
    expect(scoreLabel(0)).toBe('low');
    expect(scoreLabel(29)).toBe('low');
  });
  it('returns medium for 30-59', () => {
    expect(scoreLabel(30)).toBe('medium');
    expect(scoreLabel(59)).toBe('medium');
  });
  it('returns high for 60-79', () => {
    expect(scoreLabel(60)).toBe('high');
    expect(scoreLabel(79)).toBe('high');
  });
  it('returns critical for 80-100', () => {
    expect(scoreLabel(80)).toBe('critical');
    expect(scoreLabel(100)).toBe('critical');
  });
});

describe('scoreFile', () => {
  it('combines different rules probabilistically', () => {
    const findings = [
      { ...makeFinding('high', 'high', 30), id: 'A-001' },
      { ...makeFinding('medium', 'medium', 11), id: 'B-001' },
      { ...makeFinding('low', 'low', 3), id: 'C-001' },
    ];
    // 100 x (1 - 0.70 x 0.89 x 0.97) = 39.6
    expect(scoreFile(findings)).toBe(40);
  });

  it('counts a repeated rule once, at its highest points', () => {
    const repeats = Array.from({ length: 50 }, () => makeFinding('high', 'medium', 23));
    expect(scoreFile(repeats)).toBe(23);
  });

  it('two critical findings no longer saturate the score', () => {
    const two = [{ ...makeFinding('critical', 'high', 50), id: 'A-001' }, { ...makeFinding('critical', 'high', 50), id: 'B-001' }];
    expect(scoreFile(two)).toBe(75);
  });

  it('returns 0 for empty findings', () => {
    expect(scoreFile([])).toBe(0);
  });
});

describe('buildScanResult', () => {
  const config = { ...DEFAULT_CONFIG, threshold: 60 };

  it('passes when score is below threshold', () => {
    const fileResults: FileResult[] = [{
      file: 'test.ts',
      findings: [makeFinding('low', 'low', 5)],
      fileScore: 5,
    }];
    const result = buildScanResult(fileResults, config);
    expect(result.passed).toBe(true);
    expect(result.repoScore).toBe(5);
  });

  it('fails when score meets threshold', () => {
    const fileResults: FileResult[] = [{
      file: 'test.ts',
      findings: [makeFinding('critical', 'high', 60)],
      fileScore: 60,
    }];
    const result = buildScanResult(fileResults, config);
    expect(result.passed).toBe(false);
  });

  it('fails on critical when failOn=critical', () => {
    const cfgWithFailOn = { ...config, threshold: 100, failOn: 'critical' as const };
    const fileResults: FileResult[] = [{
      file: 'test.ts',
      findings: [makeFinding('critical', 'high', 50)],
      fileScore: 50,
    }];
    const result = buildScanResult(fileResults, cfgWithFailOn);
    expect(result.passed).toBe(false);
  });

  it('weights files worst first with halving, so repo size does not saturate the score', () => {
    const files = (n: number, score: number): FileResult[] => Array.from({ length: n }, (_, i) => ({
      file: `file${i}.ts`, findings: [makeFinding('critical', 'high', score)], fileScore: score,
    }));
    // 50, 25, 12.5, 6.25, 3.125 combined
    expect(buildScanResult(files(5, 50), config).repoScore).toBe(70);
    // Twenty files with one medium finding each stay low
    expect(buildScanResult(files(20, 11), config).repoScore).toBe(20);
    expect(buildScanResult(files(200, 100), config).repoScore).toBeLessThanOrEqual(100);
  });
});

describe('buildScanResult failures', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { buildScanResult } = require('../src/scoring/index') as typeof import('../src/scoring/index');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { DEFAULT_CONFIG } = require('../src/config/defaults') as typeof import('../src/config/defaults');
  const crit = { id: 'JBK-001', title: 't', severity: 'critical' as const, confidence: 'high' as const, evidence: 'e',
    file: 'a.prompt', lineStart: 1, lineEnd: 1, remediation: '-', riskPoints: 50 };
  const files = [{ file: 'a.prompt', findings: [crit], fileScore: 50 }];

  it('has no failures when every gate passes', () => {
    const r = buildScanResult(files, { ...DEFAULT_CONFIG, threshold: 60 });
    expect(r.passed).toBe(true);
    expect(r.failures).toBeUndefined();
  });

  it('records each failed gate with a readable reason', () => {
    const r = buildScanResult(files, { ...DEFAULT_CONFIG, threshold: 40, failOn: 'high', failFileThreshold: 45 });
    expect(r.passed).toBe(false);
    expect(r.failures).toEqual([
      { kind: 'threshold', message: 'repo score 50 is at or above the threshold of 40' },
      { kind: 'fail-on', message: '1 finding(s) at high severity or above (fail-on: high)' },
      { kind: 'file-threshold', message: '1 file(s) at or above the file threshold of 45 (highest: a.prompt with 50)' },
    ]);
  });
});
