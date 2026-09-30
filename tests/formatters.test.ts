import { buildJsonReport } from '../src/report/json';
import { buildSarifReport } from '../src/report/sarif';
import { allRules } from '../src/rules/index';
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

  it('reports the package version as the tool driver version', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const pkg = require('../package.json') as { version: string };
    const sarif = JSON.parse(buildSarifReport(makeScanResult()));
    expect(sarif.runs[0].tool.driver.version).toBe(pkg.version);
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

  it('lists every built-in rule with help and GitHub security-severity', () => {
    const sarif = JSON.parse(buildSarifReport(makeScanResult()));
    const rules = sarif.runs[0].tool.driver.rules as { id: string; help: { markdown: string }; defaultConfiguration: { level: string }; properties: Record<string, unknown> }[];
    expect(rules.length).toBe(allRules.length);
    const pst = rules.find(r => r.id === 'PST-001')!;
    expect(pst.properties['security-severity']).toBe('9.5');
    expect(pst.defaultConfiguration.level).toBe('error');
    expect(pst.properties.tags).toContain('persistence');
    expect(pst.help.markdown).toContain('hound explain PST-001');
  });

  it('points each result at its rule with ruleIndex', () => {
    const sarif = JSON.parse(buildSarifReport(makeScanResult()));
    const run = sarif.runs[0];
    const r0 = run.results[0];
    expect(run.tool.driver.rules[r0.ruleIndex].id).toBe(r0.ruleId);
  });

  it('adds rules that only appear in findings, such as plugin rules', () => {
    const plugin = makeFinding({ id: 'ACME-001', title: 'Custom rule', severity: 'medium' });
    const sarif = JSON.parse(buildSarifReport(makeScanResult({ allFindings: [plugin] })));
    const run = sarif.runs[0];
    const rule = run.tool.driver.rules[run.results[0].ruleIndex];
    expect(rule.id).toBe('ACME-001');
    expect(rule.properties['security-severity']).toBe('5.5');
  });

  it('reports skipped files and suppressions as invocation notifications', () => {
    const sarif = JSON.parse(buildSarifReport(makeScanResult({
      skippedFiles: [{ file: 'big.txt', size: 2_000_000, reason: 'max-file-size' }],
      suppressedCount: 3,
    })));
    const inv = sarif.runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(true);
    const texts = inv.toolExecutionNotifications.map((n: { message: { text: string } }) => n.message.text);
    expect(texts.some((t: string) => t.includes('big.txt'))).toBe(true);
    expect(texts.some((t: string) => t.includes('3 finding(s) suppressed'))).toBe(true);
  });

  it('tags rules with their OWASP IDs and names them in help', () => {
    const sarif = JSON.parse(buildSarifReport(makeScanResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'MCP-001');
    expect(rule.properties.tags).toEqual(expect.arrayContaining(['owasp:LLM01', 'owasp:ASI01']));
    expect(rule.help.markdown).toContain('LLM01 Prompt Injection');
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

  it('loads no external resources (no CDN src= or stylesheet href=)', () => {
    const result = makeScanResult();
    const html = buildHtmlReport(result);
    // Must not load external scripts, images, or stylesheets
    expect(html).not.toMatch(/src="https?:\/\//);
    expect(html).not.toMatch(/<link[^>]*href="https?:\/\//);
  });

  describe('untrusted content', () => {
    const payload = '</script><script>alert(document.domain)</script><!--';

    it('cannot break out of the data block via evidence or file path', () => {
      const f = makeFinding({ evidence: payload, file: `src/${payload}.ts` });
      const html = buildHtmlReport(makeScanResult({ allFindings: [f], files: [{ file: f.file, findings: [f], fileScore: 30 }] }));
      expect(html).not.toContain(payload);
      expect(html).not.toContain('<script>alert');
      // Exactly the two script elements the template defines.
      expect(html.match(/<script\b/g)).toHaveLength(2);
      expect(html.match(/<\/script>/g)).toHaveLength(2);
    });

    it('embeds finding data as inert JSON that round-trips exactly', () => {
      const evidence = `${payload} &   line-sep   para-sep`;
      const f = makeFinding({ evidence });
      const html = buildHtmlReport(makeScanResult({ allFindings: [f] }));
      const m = html.match(/<script type="application\/json" id="hound-data">([\s\S]*?)<\/script>/);
      expect(m).not.toBeNull();
      const data = JSON.parse(m![1]) as ScanResult;
      expect(data.allFindings[0].evidence).toBe(evidence);
    });

    it('escapes config-derived values rendered by the template', () => {
      const html = buildHtmlReport(makeScanResult({
        threshold: '<img src=x onerror=alert(1)>' as unknown as number,
        scoreLabel: '<b>x</b>' as unknown as ScanResult['scoreLabel'],
      }));
      expect(html).not.toContain('<img src=x');
      expect(html).not.toContain('<b>x</b>');
      expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    });

    it('ships a CSP whose script hash matches the only executable script', () => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const crypto = require('crypto') as typeof import('crypto');
      const html = buildHtmlReport(makeScanResult());
      const csp = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
      expect(csp).not.toBeNull();
      expect(csp![1]).toContain("default-src 'none'");
      const script = html.match(/<script>([\s\S]*?)<\/script>/)![1];
      const hash = crypto.createHash('sha256').update(script, 'utf8').digest('base64');
      expect(csp![1]).toContain(`script-src 'sha256-${hash}'`);
      expect(csp![1]).not.toContain('unsafe-inline\'; script');
    });
  });
});

// ── CSV formatter ─────────────────────────────────────────────────────────────

describe('CSV formatter', () => {
  it('emits a header row and one data row per finding', () => {
    const result = makeScanResult();
    const csv = buildCsvReport(result);
    const rows = csv.split('\n');
    expect(rows).toHaveLength(2); // header + 1 finding
    expect(rows[0]).toBe('rule_id,severity,confidence,file,line_start,line_end,title,evidence,remediation,mitre_technique,owasp');
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

// ── MITRE ATT&CK formatter integration ───────────────────────────────────────

describe('MITRE formatter integration', () => {
  const mitreFinding = makeFinding({ id: 'INJ-001', mitre: 'T1190' });
  const subFinding   = makeFinding({ id: 'PST-001', mitre: 'T1053.003' });
  const noMitre      = makeFinding({ id: 'TOOL-001' });

  function makeTaggedResult(): ScanResult {
    return makeScanResult({
      allFindings: [mitreFinding, subFinding, noMitre],
      files: [{ file: 'src/api.ts', findings: [mitreFinding, subFinding, noMitre], fileScore: 45 }],
    });
  }

  // JSON: automatic via JSON.stringify
  it('JSON output includes mitre field when present', () => {
    const parsed = JSON.parse(buildJsonReport(makeTaggedResult()));
    expect(parsed.allFindings[0].mitre).toBe('T1190');
    expect(parsed.allFindings[1].mitre).toBe('T1053.003');
  });

  it('JSON output omits mitre key when not set', () => {
    const parsed = JSON.parse(buildJsonReport(makeTaggedResult()));
    expect('mitre' in parsed.allFindings[2]).toBe(false);
  });

  // JSONL
  it('JSONL includes mitre field on tagged findings', () => {
    const { buildJsonlReport } = require('../src/report/jsonl');
    const lines = buildJsonlReport(makeTaggedResult()).split('\n');
    expect(JSON.parse(lines[0]).mitre).toBe('T1190');
  });

  // SARIF: tags and helpUri
  it('SARIF rule tags include attack:T1190 for tagged rule', () => {
    const sarif = JSON.parse(buildSarifReport(makeTaggedResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'INJ-001');
    expect(rule.properties.tags).toContain('attack:T1190');
  });

  it('SARIF rule tags include attack:T1053.003 for sub-technique', () => {
    const sarif = JSON.parse(buildSarifReport(makeTaggedResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'PST-001');
    expect(rule.properties.tags).toContain('attack:T1053.003');
  });

  it('SARIF rule has helpUri pointing to ATT&CK for tagged rule', () => {
    const sarif = JSON.parse(buildSarifReport(makeTaggedResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'INJ-001');
    expect(rule.helpUri).toContain('attack.mitre.org/techniques/T1190');
  });

  it('SARIF rule for sub-technique has helpUri with slash-separated path', () => {
    const sarif = JSON.parse(buildSarifReport(makeTaggedResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'PST-001');
    expect(rule.helpUri).toContain('T1053/003');
  });

  it('SARIF rule without mitre has no helpUri', () => {
    const sarif = JSON.parse(buildSarifReport(makeTaggedResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'TOOL-001');
    expect(rule.helpUri).toBeUndefined();
  });

  it('SARIF rule without mitre does not gain attack: tag', () => {
    const sarif = JSON.parse(buildSarifReport(makeTaggedResult()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'TOOL-001');
    const attackTags = (rule.properties.tags as string[]).filter(t => t.startsWith('attack:'));
    expect(attackTags).toHaveLength(0);
  });

  // CSV
  it('CSV header includes mitre_technique column', () => {
    const csv = buildCsvReport(makeTaggedResult());
    expect(csv.split('\n')[0]).toContain('mitre_technique');
  });

  it('CSV data row contains MITRE technique ID for tagged finding', () => {
    const csv = buildCsvReport(makeTaggedResult());
    expect(csv.split('\n')[1]).toContain('T1190');
  });

  it('CSV data row has empty mitre_technique for untagged finding', () => {
    const result = makeScanResult({ allFindings: [noMitre], files: [{ file: 'src/api.ts', findings: [noMitre], fileScore: 0 }] });
    const csv = buildCsvReport(result);
    // Last field in data row should be empty (no technique)
    const dataRow = csv.split('\n')[1];
    expect(dataRow.endsWith(',')).toBe(true);
  });

  // Markdown
  it('Markdown table header includes MITRE column', () => {
    const md = buildMarkdownReport(makeTaggedResult());
    expect(md).toContain('| MITRE |');
  });

  it('Markdown table row contains linked ATT&CK technique', () => {
    const md = buildMarkdownReport(makeTaggedResult());
    expect(md).toContain('[T1190](https://attack.mitre.org/techniques/T1190)');
  });

  it('Markdown detail block includes MITRE ATT&CK link for tagged finding', () => {
    const md = buildMarkdownReport(makeTaggedResult());
    expect(md).toContain('**MITRE ATT&CK:**');
    expect(md).toContain('T1053/003');
  });

  // JUnit
  it('JUnit failure body includes MITRE ATT&CK line for tagged finding', () => {
    const xml = buildJunitReport(makeTaggedResult());
    expect(xml).toContain('MITRE ATT&amp;CK: T1190');
  });

  it('JUnit failure body has no MITRE line for untagged finding', () => {
    const result = makeScanResult({ allFindings: [noMitre], files: [{ file: 'src/api.ts', findings: [noMitre], fileScore: 0 }] });
    const xml = buildJunitReport(result);
    expect(xml).not.toContain('MITRE ATT');
  });
});

// ── Output escaping (untrusted scanned content) ───────────────────────────────

describe('output escaping', () => {
  it('CSV neutralises formula injection in any text cell', () => {
    for (const lead of ['=', '+', '-', '@', '\t', '\r']) {
      const f = makeFinding({ evidence: `${lead}HYPERLINK("http://evil.example","x")` });
      const csv = buildCsvReport(makeScanResult({ allFindings: [f] }));
      const evidenceCell = csv.split('\n').slice(1).join('\n');
      expect(evidenceCell).toContain(`'${lead}HYPERLINK`);
    }
  });

  it('CSV leaves ordinary values and line numbers untouched', () => {
    const csv = buildCsvReport(makeScanResult());
    expect(csv.split('\n')[1]).toMatch(/^INJ-001,high,high,src\/api\.ts,42,42,/);
  });

  it('GitHub annotations cannot inject workflow commands via file names', () => {
    const f = makeFinding({ file: 'src/a,b:c.ts\n::add-mask::secret' });
    const out = buildGithubAnnotationsReport(makeScanResult({ allFindings: [f] }));
    expect(out.split('\n')).toHaveLength(1);
    expect(out).toContain('file=src/a%2Cb%3Ac.ts%0A%3A%3Aadd-mask%3A%3Asecret,');
  });

  it('Markdown evidence cannot escape its code span', () => {
    const evidence = 'x` ![t](https://evil.example/p.png) [fix](https://evil.example) `y';
    const f = makeFinding({ evidence, file: 'src/`weird`.ts' });
    const md = buildMarkdownReport(makeScanResult({ allFindings: [f], files: [{ file: f.file, findings: [f], fileScore: 30 }] }));
    expect(md).toContain('**Evidence:** ``' + evidence + '``');
    expect(md).toContain('### ``src/`weird`.ts``');
  });

  it('Markdown escapes titles in HTML summaries and table cells', () => {
    const f = makeFinding({ title: 'a | b <img src=x onerror=alert(1)>' });
    const md = buildMarkdownReport(makeScanResult({ allFindings: [f], files: [{ file: f.file, findings: [f], fileScore: 30 }] }));
    expect(md).not.toContain('<img');
    expect(md).toContain('a \\| b');
  });

  it('JUnit output drops characters that are illegal in XML', () => {
    const f = makeFinding({ evidence: 'a\u0000b\u001bc' });
    const xml = buildJunitReport(makeScanResult({ allFindings: [f] }));
    expect(xml).toContain('Evidence: abc');
  });
});

describe('sanitize helpers', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { toTerminalSafe, markdownCode } = require('../src/report/sanitize') as typeof import('../src/report/sanitize');

  it('renders terminal escapes, bidi overrides and zero-width chars visibly', () => {
    expect(toTerminalSafe('ok\u001b]52;c;ZXZpbA==\u0007')).toBe('ok<U+001B>]52;c;ZXZpbA==<U+0007>');
    expect(toTerminalSafe('a‮b​c')).toBe('a<U+202E>b<U+200B>c');
    expect(toTerminalSafe('tab\tkept')).toBe('tab\tkept');
  });

  it('markdownCode picks a fence longer than any backtick run', () => {
    expect(markdownCode('plain')).toBe('`plain`');
    expect(markdownCode('a ``b`` c')).toBe('```a ``b`` c```');
    expect(markdownCode('`edge`')).toBe('`` `edge` ``');
  });
});
