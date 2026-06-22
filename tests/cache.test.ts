import fs from 'fs';
import os from 'os';
import path from 'path';
import { computeCacheSignature, loadCache, saveCache } from '../src/scanner/cache';
import type { Rule } from '../src/rules/types';

function makeRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'TST-001',
    title: 'Test rule',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    remediation: 'Fix it.',
    check: () => [],
    ...overrides,
  };
}

describe('cache signature', () => {
  it('is stable across calls for the same ruleset and config', () => {
    const rules = [makeRule()];
    const a = computeCacheSignature(rules, {});
    const b = computeCacheSignature(rules, {});
    expect(a).toBe(b);
  });

  it('ignores rule registration order', () => {
    const r1 = makeRule({ id: 'AAA-001' });
    const r2 = makeRule({ id: 'BBB-002' });
    expect(computeCacheSignature([r1, r2], {})).toBe(computeCacheSignature([r2, r1], {}));
  });

  it('changes when a rule is added (ruleset upgrade)', () => {
    const base = computeCacheSignature([makeRule({ id: 'AAA-001' })], {});
    const upgraded = computeCacheSignature(
      [makeRule({ id: 'AAA-001' }), makeRule({ id: 'AAA-002' })],
      {},
    );
    expect(upgraded).not.toBe(base);
  });

  it("changes when a rule's check logic changes", () => {
    const before = computeCacheSignature([makeRule({ check: () => [] })], {});
    const after = computeCacheSignature([
      makeRule({ check: (p) => (p.text ? [] : []) }),
    ], {});
    expect(after).not.toBe(before);
  });

  it('changes when rule severity/confidence changes', () => {
    const before = computeCacheSignature([makeRule({ severity: 'high' })], {});
    const after = computeCacheSignature([makeRule({ severity: 'low' })], {});
    expect(after).not.toBe(before);
  });

  it('changes when findings-affecting config changes', () => {
    const rules = [makeRule()];
    const base = computeCacheSignature(rules, {});
    expect(computeCacheSignature(rules, { minConfidence: 'high' })).not.toBe(base);
    expect(computeCacheSignature(rules, { includeRules: ['TST-*'] })).not.toBe(base);
    expect(computeCacheSignature(rules, { excludeRules: ['TST-001'] })).not.toBe(base);
  });

  it('ignores include/exclude ordering', () => {
    const rules = [makeRule()];
    const a = computeCacheSignature(rules, { excludeRules: ['A', 'B'] });
    const b = computeCacheSignature(rules, { excludeRules: ['B', 'A'] });
    expect(a).toBe(b);
  });
});

describe('loadCache invalidation', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-cache-unit-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns a fresh cache when none exists', () => {
    const cache = loadCache(tmpDir, 'sig-1');
    expect(cache.version).toBe('sig-1');
    expect(cache.entries).toEqual({});
  });

  it('preserves entries when the signature matches', () => {
    const cache = loadCache(tmpDir, 'sig-1');
    cache.entries['/x.ts'] = { mtime: 1, findings: [] };
    saveCache(tmpDir, cache);

    const reloaded = loadCache(tmpDir, 'sig-1');
    expect(reloaded.entries['/x.ts']).toBeDefined();
  });

  it('discards entries when the signature differs (stale ruleset/config)', () => {
    const cache = loadCache(tmpDir, 'sig-1');
    cache.entries['/x.ts'] = { mtime: 1, findings: [] };
    saveCache(tmpDir, cache);

    const reloaded = loadCache(tmpDir, 'sig-2');
    expect(reloaded.version).toBe('sig-2');
    expect(reloaded.entries).toEqual({});
  });

  it('recovers from a corrupt cache file', () => {
    fs.writeFileSync(path.join(tmpDir, '.hound-cache.json'), '{ not json');
    const cache = loadCache(tmpDir, 'sig-1');
    expect(cache.entries).toEqual({});
  });
});
