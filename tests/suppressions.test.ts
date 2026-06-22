import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseSuppressions, applySuppressions } from '../src/scanner/suppressions';
import { runScan } from '../src/scanner/pipeline';
import { DEFAULT_CONFIG } from '../src/config/defaults';
import type { Finding } from '../src/types';

function finding(id: string, line: number): Finding {
  return {
    id, title: id, severity: 'high', confidence: 'high',
    evidence: 'x', file: 'f.ts', lineStart: line, lineEnd: line,
    remediation: '', riskPoints: 30,
  };
}

describe('parseSuppressions', () => {
  it('parses disable-line on the same line', () => {
    const d = parseSuppressions('a\nbad code // hound-disable-line INJ-001\nc');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ type: 'line', startLine: 2, endLine: 2, ruleIds: ['INJ-001'] });
  });

  it('parses disable-next-line targeting the following line', () => {
    const d = parseSuppressions('// hound-disable-next-line RAG-007\nbad code');
    expect(d[0]).toMatchObject({ type: 'next-line', startLine: 2, endLine: 2, ruleIds: ['RAG-007'] });
  });

  it('captures a reason after --', () => {
    const d = parseSuppressions('// hound-disable-line INJ-001 -- input is a constant');
    expect(d[0].reason).toBe('input is a constant');
    expect(d[0].ruleIds).toEqual(['INJ-001']);
  });

  it('treats a directive with no rule IDs as suppress-all', () => {
    const d = parseSuppressions('// hound-disable-line');
    expect(d[0].ruleIds).toBeNull();
  });

  it('parses multiple comma/space separated rule IDs', () => {
    const d = parseSuppressions('// hound-disable-line INJ-001, RAG-007 CMD-006');
    expect(d[0].ruleIds).toEqual(['INJ-001', 'RAG-007', 'CMD-006']);
  });

  it('covers a block between disable and enable', () => {
    const src = 'l1\n// hound-disable INJ-001\nl3\nl4\n// hound-enable INJ-001\nl6';
    const d = parseSuppressions(src);
    expect(d[0]).toMatchObject({ type: 'block', startLine: 2, endLine: 5, ruleIds: ['INJ-001'] });
  });

  it('leaves an unclosed block open until end of file', () => {
    const src = 'l1\n// hound-disable\nl3\nl4';
    const d = parseSuppressions(src);
    expect(d[0]).toMatchObject({ type: 'block', startLine: 2, endLine: 4 });
  });
});

describe('applySuppressions', () => {
  it('suppresses a matching finding and flags the directive used', () => {
    const directives = parseSuppressions('// hound-disable-next-line INJ-001\nx');
    const { kept, suppressedCount } = applySuppressions([finding('INJ-001', 2)], directives);
    expect(kept).toHaveLength(0);
    expect(suppressedCount).toBe(1);
    expect(directives[0].used).toBe(true);
  });

  it('does not suppress a different rule on the same line', () => {
    const directives = parseSuppressions('// hound-disable-next-line INJ-001\nx');
    const { kept } = applySuppressions([finding('RAG-007', 2)], directives);
    expect(kept).toHaveLength(1);
  });

  it('does not suppress findings outside the targeted line', () => {
    const directives = parseSuppressions('// hound-disable-next-line INJ-001\nx');
    const { kept } = applySuppressions([finding('INJ-001', 5)], directives);
    expect(kept).toHaveLength(1);
  });

  it('suppress-all silences any rule on the line', () => {
    const directives = parseSuppressions('// hound-disable-line\nignored');
    const r1 = applySuppressions([finding('INJ-001', 1)], parseSuppressions('// hound-disable-line\nx'));
    expect(r1.kept).toHaveLength(0);
    void directives;
  });
});

describe('runScan integration', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-supp-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  const cfg = (extra = {}) => ({
    ...DEFAULT_CONFIG, include: ['**/*.ts'], exclude: [], cache: false, ...extra,
  });

  it('suppresses an interpolation finding with disable-next-line', async () => {
    const code = [
      'const messages = [',
      '  // hound-disable-next-line INJ-001',
      '  { role: "system", content: `Answer using ${userInput} now please` },',
      '];',
    ].join('\n');
    fs.writeFileSync(path.join(tmpDir, 'a.ts'), code);

    const withSup = await runScan(tmpDir, cfg());
    fs.writeFileSync(path.join(tmpDir, 'a.ts'), code.replace('  // hound-disable-next-line INJ-001\n', ''));
    const without = await runScan(tmpDir, cfg());

    expect(without.allFindings.some(f => f.id === 'INJ-001')).toBe(true);
    expect(withSup.allFindings.some(f => f.id === 'INJ-001')).toBe(false);
    expect(withSup.suppressedCount).toBeGreaterThan(0);
  });

  it('reports unused suppressions when enabled', async () => {
    const code = [
      '// hound-disable-next-line INJ-001 -- nothing here',
      'const x = 1;',
    ].join('\n');
    fs.writeFileSync(path.join(tmpDir, 'b.ts'), code);

    const result = await runScan(tmpDir, cfg({ reportUnusedSuppressions: true }));
    expect(result.unusedSuppressions?.length).toBe(1);
    expect(result.unusedSuppressions![0]).toMatchObject({ line: 1, ruleIds: ['INJ-001'], reason: 'nothing here' });
  });
});
