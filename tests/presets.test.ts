import { PRESETS, resolvePresets } from '../src/config/presets';

describe('resolvePresets', () => {
  it('resolves a single preset to its rule patterns', () => {
    expect(resolvePresets('mcp')).toEqual(['MCP-*']);
  });

  it('is case-insensitive and trims whitespace', () => {
    expect(resolvePresets('  MCP ')).toEqual(['MCP-*']);
  });

  it('unions and dedupes multiple comma/space separated presets', () => {
    const r = resolvePresets('injection, jailbreak');
    expect(r).toEqual(expect.arrayContaining(['INJ-*', 'RAG-*', 'ENC-*', 'JBK-*']));
    // dedupe: INJ-* appears once even though multiple presets could include it
    expect(r.filter(x => x === 'INJ-*')).toHaveLength(1);
  });

  it('throws a helpful error for an unknown preset', () => {
    expect(() => resolvePresets('nope')).toThrow(/Unknown preset "nope"/);
    expect(() => resolvePresets('nope')).toThrow(/Available:/);
  });

  it('every preset has a description and at least one rule pattern', () => {
    for (const [, preset] of Object.entries(PRESETS)) {
      expect(preset.description.length).toBeGreaterThan(0);
      expect(preset.rules.length).toBeGreaterThan(0);
      for (const r of preset.rules) expect(r).toMatch(/^[A-Z]+-\*$|^[A-Z]+-\d+$/);
    }
  });
});
