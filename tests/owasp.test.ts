import { allRules, OWASP_BY_RULE, OWASP_CATEGORIES, owaspLabel, ruleToFinding } from '../src/rules/index';
import { PRESETS } from '../src/config/presets';
import { buildCsvReport } from '../src/report/csv';

describe('OWASP mapping', () => {
  it('gives every built-in rule at least one OWASP ID', () => {
    const missing = allRules.filter(r => !r.owasp?.length).map(r => r.id);
    expect(missing).toEqual([]);
  });

  it('only uses known category IDs', () => {
    const unknown = allRules.flatMap(r => (r.owasp ?? []).filter(id => !OWASP_CATEGORIES[id]));
    expect(unknown).toEqual([]);
  });

  it('has no entries for rules that do not exist', () => {
    const ids = new Set(allRules.map(r => r.id));
    expect(Object.keys(OWASP_BY_RULE).filter(id => !ids.has(id))).toEqual([]);
  });

  it('covers every category of both lists', () => {
    const used = new Set(allRules.flatMap(r => r.owasp ?? []));
    expect(Object.keys(OWASP_CATEGORIES).filter(id => !used.has(id))).toEqual([]);
  });

  it('labels IDs with their category name', () => {
    expect(owaspLabel('LLM07')).toBe('LLM07 System Prompt Leakage');
    expect(owaspLabel('ASI05')).toBe('ASI05 Unexpected Code Execution');
    expect(owaspLabel('X')).toBe('X');
  });

  it('copies OWASP IDs onto findings and into the CSV report', () => {
    const rule = allRules.find(r => r.id === 'EXF-007')!;
    const finding = ruleToFinding(rule, { evidence: 'x', lineStart: 1, lineEnd: 1 }, 'a.md');
    expect(finding.owasp).toEqual(['LLM02', 'LLM07']);
    const csv = buildCsvReport({
      repoScore: 10, scoreLabel: 'low', threshold: 60, passed: true,
      files: [{ file: 'a.md', findings: [finding], fileScore: 10 }], allFindings: [finding],
    });
    expect(csv.split('\n')[1].endsWith(',LLM02;LLM07')).toBe(true);
  });

  it('builds the OWASP presets from the mapping', () => {
    const llm = PRESETS['owasp-llm-top10'].rules;
    const asi = PRESETS['owasp-agentic'].rules;
    expect(llm).toContain('INJ-001');
    expect(llm).toContain('DOS-001');
    expect(llm).not.toContain('AGT-005'); // agentic-only
    expect(asi).toContain('AGT-005');
    expect(asi).not.toContain('INJ-001'); // LLM-only
  });
});
