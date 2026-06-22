// eslint-disable-next-line @typescript-eslint/no-require-imports
const { computePerRule } = require('../scripts/benchmark.js');

interface RuleMetric {
  id: string;
  tp: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

const labels = {
  safe: [{ file: 'safe-a.ts' }, { file: 'safe-b.ts' }],
  unsafe: [
    { file: 'u1.ts', expectFindings: ['INJ-001'] },
    { file: 'u2.ts', expectFindings: ['CMD-001'] },
  ],
};

describe('computePerRule', () => {
  it('computes precision/recall/F1 for a perfect rule', () => {
    const safeMap = {};
    const unsafeMap = { 'u1.ts': ['INJ-001'], 'u2.ts': ['CMD-001'] };
    const rows: RuleMetric[] = computePerRule(labels, safeMap, unsafeMap);
    const inj = rows.find(r => r.id === 'INJ-001')!;
    expect(inj).toMatchObject({ tp: 1, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 });
  });

  it('counts safe-fixture hits as false positives', () => {
    const safeMap = { 'safe-a.ts': ['DOS-001'], 'safe-b.ts': ['DOS-001'] };
    const unsafeMap = { 'u1.ts': ['INJ-001'], 'u2.ts': ['CMD-001'] };
    const rows: RuleMetric[] = computePerRule(labels, safeMap, unsafeMap);
    const dos = rows.find(r => r.id === 'DOS-001')!;
    expect(dos).toMatchObject({ tp: 0, fp: 2, fn: 0, precision: 0, recall: null });
  });

  it('counts a missed expected rule as a false negative (recall < 1)', () => {
    const safeMap = {};
    const unsafeMap = { 'u1.ts': [], 'u2.ts': ['CMD-001'] }; // INJ-001 missed
    const rows: RuleMetric[] = computePerRule(labels, safeMap, unsafeMap);
    const inj = rows.find(r => r.id === 'INJ-001')!;
    expect(inj).toMatchObject({ tp: 0, fn: 1, recall: 0 });
  });

  it('ranks worst-signal rules first', () => {
    const safeMap = { 'safe-a.ts': ['DOS-001'] };
    const unsafeMap = { 'u1.ts': ['INJ-001'], 'u2.ts': ['CMD-001'] };
    const rows: RuleMetric[] = computePerRule(labels, safeMap, unsafeMap);
    expect(rows[0].id).toBe('DOS-001'); // FP-only rule sorts ahead of perfect ones
  });
});
