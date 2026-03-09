import { buildJsonReport } from '../src/report/json';
import { buildSarifReport } from '../src/report/sarif';
import { buildGithubAnnotationsReport } from '../src/report/githubAnnotations';
import { buildMarkdownReport } from '../src/report/markdown';
import { buildJsonlReport } from '../src/report/jsonl';
import { buildHtmlReport } from '../src/report/html';
import { buildCsvReport } from '../src/report/csv';
import { buildJunitReport } from '../src/report/junit';
import type { ScanResult, Finding } from '../src/types';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'INJ-001',
    title: 'Direct user input concatenated without delimiter',
    severity: 'high',
    confidence: 'high',
    evidence: '${userInput}',
    file: 'src/api.ts',
    lineStart: 42,
    lineEnd: 42,
    remediation: 'Wrap user input in delimiters.',
    riskPoints: 30,
    ...overrides,
  };
}

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const finding = makeFinding();
  return {
    repoScore: 30,
    scoreLabel: 'medium',
    files: [{
      file: 'src/api.ts',
      findings: [finding],
      fileScore: 30,
    }],
    allFindings: [finding],
    threshold: 60,
    passed: true,
    ...overrides,
  };
}

// ── JSON formatter ────────────────────────────────────────────────────────────

describe('JSON formatter', () => {
  it('round-trips ScanResult correctly', () => {
    const result = makeScanResult();
    const json = buildJsonReport(result);
    const parsed = JSON.parse(json) as ScanResult;
    expect(parsed.repoScore).toBe(result.repoScore);
    expect(parsed.passed).toBe(result.passed);
    expect(parsed.allFindings).toHaveLength(1);
    expect(parsed.allFindings[0].id).toBe('INJ-001');
  });

  it('produces valid JSON', () => {
    const result = makeScanResult();
    expect(() => JSON.parse(buildJsonReport(result))).not.toThrow();
  });
});

// ── SARIF formatter ───────────────────────────────────────────────────────────

describe('SARIF formatter', () => {
  it('emits valid SARIF 2.1.0 structure', () => {
    const result = makeScanResult();
    const sarif = JSON.parse(buildSarifReport(result));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('ContextHound');
  });

  it('includes correct rule IDs in tool driver', () => {
    const result = makeScanResult();
    const sarif = JSON.parse(buildSarifReport(result));
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toContain('INJ-001');
  });

  it('maps findings to results with correct ruleId', () => {
    const result = makeScanResult();
    const sarif = JSON.parse(buildSarifReport(result));
    const sarifResult = sarif.runs[0].results[0];
    expect(sarifResult.ruleId).toBe('INJ-001');
    expect(sarifResult.level).toBe('error'); // high → error
  });

  it('maps medium severity to warning', () => {
    const result = makeScanResult({
      allFindings: [makeFinding({ severity: 'medium', id: 'INJ-002' })],
      files: [{ file: 'src/api.ts', findings: [makeFinding({ severity: 'medium', id: 'INJ-002' })], fileScore: 10 }],
    });
    const sarif = JSON.parse(buildSarifReport(result));
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('maps low severity to note', () => {
    const result = makeScanResult({
      allFindings: [makeFinding({ severity: 'low', id: 'INJ-002' })],
      files: [{ file: 'src/api.ts', findings: [makeFinding({ severity: 'low', id: 'INJ-002' })], fileScore: 5 }],
    });
    const sarif = JSON.parse(buildSarifReport(result));
    expect(sarif.runs[0].results[0].level).toBe('note');
  });
});

// ── GitHub Annotations formatter ──────────────────────────────────────────────

describe('GitHub Annotations formatter', () => {
  it('emits ::error for high severity findings', () => {
    const result = makeScanResult();
    const output = buildGithubAnnotationsReport(result);
    expect(output).toContain('::error');
    expect(output).toContain('INJ-001');
    expect(output).toContain('src/api.ts');
    expect(output).toContain('line=42');
  });

  it('emits ::warning for medium severity', () => {
    const finding = makeFinding({ severity: 'medium', id: 'INJ-002' });
    const result = makeScanResult({ allFindings: [finding], files: [{ file: 'src/api.ts', findings: [finding], fileScore: 10 }] });
    const output = buildGithubAnnotationsReport(result);
    expect(output).toContain('::warning');
  });

  it('emits ::notice for low severity', () => {
    const finding = makeFinding({ severity: 'low', id: 'INJ-002' });
    const result = makeScanResult({ allFindings: [finding], files: [{ file: 'src/api.ts', findings: [finding], fileScore: 5 }] });
    const output = buildGithubAnnotationsReport(result);
    expect(output).toContain('::notice');
  });

  it('emits ::error for critical severity', () => {
    const finding = makeFinding({ severity: 'critical', id: 'EXF-001' });
    const result = makeScanResult({ allFindings: [finding], files: [{ file: 'src/api.ts', findings: [finding], fileScore: 50 }] });
    const output = buildGithubAnnotationsReport(result);
    expect(output).toContain('::error');
  });

  it('returns empty string for no findings', () => {
    const result = makeScanResult({ allFindings: [], files: [] });
    const output = buildGithubAnnotationsReport(result);
    expect(output).toBe('');
  });
});

// ── Markdown formatter ────────────────────────────────────────────────────────

describe('Markdown formatter', () => {
  it('produces GFM output with correct finding count', () => {
    const result = makeScanResult();
    const md = buildMarkdownReport(result);
    expect(md).toContain('# ContextHound Scan Report');
    expect(md).toContain('INJ-001');
    expect(md).toContain('src/api.ts');
  });

  it('includes PASSED badge when passed', () => {
    const result = makeScanResult({ passed: true });
    const md = buildMarkdownReport(result);
    expect(md).toContain('PASSED');
  });

  it('includes FAILED badge when failed', () => {
    const result = makeScanResult({ passed: false });
    const md = buildMarkdownReport(result);
    expect(md).toContain('FAILED');
  });

  it('includes severity summary table', () => {
    const result = makeScanResult();
    const md = buildMarkdownReport(result);
    expect(md).toContain('## Severity Summary');
    expect(md).toContain('| Severity | Count |');
  });

  it('includes remediation accordion', () => {
    const result = makeScanResult();
    const md = buildMarkdownReport(result);
    expect(md).toContain('<details>');
    expect(md).toContain('Remediation');
  });
});

// ── JSONL formatter ───────────────────────────────────────────────────────────

describe('JSONL formatter', () => {
  it('emits one JSON object per finding', () => {
    const findings = [
      makeFinding({ id: 'INJ-001', lineStart: 1 }),
      makeFinding({ id: 'EXF-001', lineStart: 2 }),
    ];
    const result = makeScanResult({
      allFindings: findings,
      files: [{ file: 'src/api.ts', findings, fileScore: 60 }],
    });
    const output = buildJsonlReport(result);
    const lines = output.split('\n').filter(l => l.trim());
    expect(lines).toHaveLength(2);
  });

  it('each line is parseable JSON', () => {
    const result = makeScanResult();
    const output = buildJsonlReport(result);
    const lines = output.split('\n').filter(l => l.trim());
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it('each JSONL object contains expected finding fields', () => {
    const result = makeScanResult();
    const output = buildJsonlReport(result);
    const parsed = JSON.parse(output.split('\n')[0]) as Finding;
    expect(parsed.id).toBe('INJ-001');
    expect(parsed.severity).toBe('high');
    expect(parsed.file).toBe('src/api.ts');
  });

  it('returns empty string for no findings', () => {
    const result = makeScanResult({ allFindings: [], files: [] });
    const output = buildJsonlReport(result);
    expect(output).toBe('');
  });
});

// ── HTML formatter ────────────────────────────────────────────────────────────

describe('HTML formatter', () => {
  it('produces a valid HTML document', () => {
    const result = makeScanResult();
    const html = buildHtmlReport(result);
    expect(html).toMatch(/<!DOCTYPE html>/i);
    expect(html).toContain('<html');
    expect(html).toContain('</html>');
  });

  it('embeds the scan score', () => {
    const result = makeScanResult({ repoScore: 30 });
    const html = buildHtmlReport(result);
    expect(html).toContain('30');
  });

  it('shows PASSED when scan passes', () => {
    const result = makeScanResult({ passed: true });
    const html = buildHtmlReport(result);
    expect(html).toContain('PASSED');
  });

  it('shows FAILED when scan fails', () => {
    const result = makeScanResult({ passed: false });
    const html = buildHtmlReport(result);
    expect(html).toContain('FAILED');
  });

  it('inlines finding data as JSON', () => {
    const result = makeScanResult();
    const html = buildHtmlReport(result);
    expect(html).toContain('INJ-001');
    expect(html).toContain('src/api.ts');
  });

  it('includes severity filter buttons', () => {
    const result = makeScanResult();
    const html = buildHtmlReport(result);
    expect(html).toContain('data-sev="critical"');
    expect(html).toContain('data-sev="high"');
  });

  it('is self-contained (no external URLs)', () => {
    const result = makeScanResult();
    const html = buildHtmlReport(result);
    expect(html).not.toMatch(/src="https?:\/\//);
    expect(html).not.toMatch(/href="https?:\/\//);
  });
});

// ── CSV formatter ─────────────────────────────────────────────────────────────

describe('CSV formatter', () => {
  it('emits a header row and one data row per finding', () => {
    const result = makeScanResult();
    const csv = buildCsvReport(result);
    const rows = csv.split('\n');
    expect(rows).toHaveLength(2); // header + 1 finding
    expect(rows[0]).toBe('rule_id,severity,confidence,file,line_start,line_end,title,evidence,remediation');
  });

  it('includes all finding fields in the correct column order', () => {
    const result = makeScanResult();
    const csv = buildCsvReport(result);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('INJ-001');
    expect(dataRow).toContain('high');
    expect(dataRow).toContain('src/api.ts');
    expect(dataRow).toContain('42');
  });

  it('wraps fields containing commas in double-quotes', () => {
    const finding = makeFinding({ title: 'Title, with comma' });
    const result = makeScanResult({ allFindings: [finding], files: [{ file: 'src/api.ts', findings: [finding], fileScore: 30 }] });
    const csv = buildCsvReport(result);
    expect(csv).toContain('"Title, with comma"');
  });

  it('escapes embedded double-quotes by doubling them', () => {
    const finding = makeFinding({ evidence: 'say "hello"' });
    const result = makeScanResult({ allFindings: [finding], files: [{ file: 'src/api.ts', findings: [finding], fileScore: 30 }] });
    const csv = buildCsvReport(result);
    expect(csv).toContain('"say ""hello"""');
  });

  it('returns only the header row when there are no findings', () => {
    const result = makeScanResult({ allFindings: [], files: [] });
    const csv = buildCsvReport(result);
    const rows = csv.split('\n').filter(r => r.trim());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain('rule_id');
  });

  it('emits one row per finding with multiple findings', () => {
    const findings = [
      makeFinding({ id: 'INJ-001', lineStart: 1 }),
      makeFinding({ id: 'EXF-001', lineStart: 2 }),
    ];
    const result = makeScanResult({
      allFindings: findings,
      files: [{ file: 'src/api.ts', findings, fileScore: 60 }],
    });
    const csv = buildCsvReport(result);
    const rows = csv.split('\n');
    expect(rows).toHaveLength(3); // header + 2 findings
  });
});

// ── JUnit XML formatter ───────────────────────────────────────────────────────

describe('JUnit XML formatter', () => {
  it('produces a valid XML declaration and testsuites root', () => {
    const result = makeScanResult();
    const xml = buildJunitReport(result);
    expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(xml).toContain('<testsuites');
    expect(xml).toContain('</testsuites>');
  });

  it('groups findings into a testsuite per file', () => {
    const result = makeScanResult();
    const xml = buildJunitReport(result);
    expect(xml).toContain('<testsuite name="src/api.ts"');
    expect(xml).toContain('</testsuite>');
  });

  it('emits one testcase with a failure element per finding', () => {
    const result = makeScanResult();
    const xml = buildJunitReport(result);
    expect(xml).toContain('<testcase');
    expect(xml).toContain('<failure');
    expect(xml).toContain('INJ-001');
  });

  it('sets tests and failures counts on testsuites', () => {
    const result = makeScanResult();
    const xml = buildJunitReport(result);
    expect(xml).toContain('tests="1"');
    expect(xml).toContain('failures="1"');
  });

  it('escapes XML special characters in evidence', () => {
    const finding = makeFinding({ evidence: '<script>alert("xss")</script>' });
    const result = makeScanResult({ allFindings: [finding], files: [{ file: 'src/api.ts', findings: [finding], fileScore: 30 }] });
    const xml = buildJunitReport(result);
    expect(xml).toContain('&lt;script&gt;');
    expect(xml).not.toContain('<script>');
  });

  it('emits testsuites for each file that has findings', () => {
    const f1 = makeFinding({ id: 'INJ-001', file: 'src/a.ts' });
    const f2 = makeFinding({ id: 'EXF-001', file: 'src/b.ts' });
    const result = makeScanResult({
      allFindings: [f1, f2],
      files: [
        { file: 'src/a.ts', findings: [f1], fileScore: 30 },
        { file: 'src/b.ts', findings: [f2], fileScore: 30 },
      ],
    });
    const xml = buildJunitReport(result);
    expect(xml).toContain('name="src/a.ts"');
    expect(xml).toContain('name="src/b.ts"');
  });

  it('produces empty testsuites element when there are no findings', () => {
    const result = makeScanResult({ allFindings: [], files: [] });
    const xml = buildJunitReport(result);
    expect(xml).toContain('<testsuites');
    expect(xml).toContain('tests="0"');
    expect(xml).not.toContain('<testsuite ');
  });
});
