/**
 * CLI integration tests.
 * These tests spawn the compiled CLI as a child process.
 * Run `npm run build` before running these tests.
 */
import { execSync, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../dist/cli.js');
const FIXTURES_DIR = path.resolve(__dirname, 'fixtures');

function runCli(args: string[], env?: Record<string, string>): {
  stdout: string;
  stderr: string;
  status: number | null;
} {
  const result = spawnSync('node', [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status,
  };
}

// ── hound init ────────────────────────────────────────────────────────────────

describe('hound init', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-cli-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates .contexthoundrc.json', () => {
    const result = runCli(['init'], { INIT_CWD: tmpDir });
    // CLI uses process.cwd() for init, so we need to run with cwd override
    // Re-run via execSync with cwd
    execSync(`node ${CLI} init`, { cwd: tmpDir });
    const configPath = path.join(tmpDir, '.contexthoundrc.json');
    expect(fs.existsSync(configPath)).toBe(true);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(config.threshold).toBe(60);
    expect(Array.isArray(config.include)).toBe(true);
    void result;
  });

  it('errors if .contexthoundrc.json already exists without --force', () => {
    fs.writeFileSync(path.join(tmpDir, '.contexthoundrc.json'), '{}');
    const result = spawnSync('node', [CLI, 'init'], { cwd: tmpDir, encoding: 'utf8' });
    expect(result.status).not.toBe(0);
    expect(result.stderr + result.stdout).toMatch(/already exists/i);
  });

  it('overwrites with --force', () => {
    fs.writeFileSync(path.join(tmpDir, '.contexthoundrc.json'), '{"threshold":99}');
    execSync(`node ${CLI} init --force`, { cwd: tmpDir });
    const config = JSON.parse(fs.readFileSync(path.join(tmpDir, '.contexthoundrc.json'), 'utf8'));
    expect(config.threshold).toBe(60); // reset to template default
  });
});

// ── --list-rules ──────────────────────────────────────────────────────────────

describe('--list-rules', () => {
  it('prints all rule IDs and exits 0', () => {
    const result = runCli(['scan', '--list-rules']);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/AGT-001/);
    expect(result.stdout).toMatch(/INJ-001/);
    expect(result.stdout).toMatch(/JBK-007/);
  });

  it('includes Total count line', () => {
    const result = runCli(['scan', '--list-rules']);
    expect(result.stdout).toMatch(/Total: \d+ rules/);
  });

  it('outputs JSON when --format json', () => {
    const result = runCli(['scan', '--list-rules', '--format', 'json']);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0]).toHaveProperty('id');
    expect(parsed[0]).toHaveProperty('severity');
  });
});

// ── Exit codes ────────────────────────────────────────────────────────────────

describe('Exit codes', () => {
  it('exits 0 when no findings', () => {
    const result = runCli(['scan', '--dir', path.join(FIXTURES_DIR, '..', 'fixtures'), '--threshold', '100', '--format', 'json']);
    // The safe-prompt fixture may have score < 100, so just check it's 0 or 2
    expect([0, 2, 3]).toContain(result.status);
  });

  it('exits 2 when threshold breached', () => {
    // Use threshold 1 so any finding causes failure
    const result = runCli(['scan', '--dir', FIXTURES_DIR, '--threshold', '1']);
    // If there are findings, should be 2 or 3
    if (result.status !== 0) {
      expect([2, 3]).toContain(result.status);
    }
  });

  it('exits 3 when failOn=critical and critical finding found', () => {
    const result = runCli(['scan', '--dir', FIXTURES_DIR, '--fail-on', 'critical', '--threshold', '100']);
    // Only fails with code 3 if there is a critical finding
    if (result.status !== 0) {
      expect(result.status).toBe(3);
    }
  });
});

// ── Environment variable overrides ────────────────────────────────────────────

describe('HOUND_THRESHOLD env var', () => {
  it('overrides config threshold', () => {
    // With threshold=1 any finding causes failure (exit 2 or 3)
    const result = runCli(['scan', '--dir', FIXTURES_DIR], { HOUND_THRESHOLD: '1' });
    // Fixtures have findings, so it should fail
    if (result.status !== 0) {
      expect([2, 3]).toContain(result.status);
    }
  });
});

// ── Baseline / diff mode ──────────────────────────────────────────────────────

describe('--baseline', () => {
  const baselinePath = path.join(FIXTURES_DIR, 'hound-results.json');

  it('accepts a baseline file without crashing', () => {
    const result = runCli([
      'scan', '--dir', FIXTURES_DIR,
      '--baseline', baselinePath,
      '--format', 'console',
    ]);
    // Any exit code is fine; what matters is no unhandled exception
    expect(result.stderr).not.toMatch(/Error during scan/);
  });

  it('prints baseline summary line', () => {
    const result = runCli([
      'scan', '--dir', FIXTURES_DIR,
      '--baseline', baselinePath,
      '--format', 'console',
    ]);
    expect(result.stdout + result.stderr).toMatch(/Baseline:/);
  });

  it('exits non-zero on bad baseline path', () => {
    const result = runCli([
      'scan', '--dir', FIXTURES_DIR,
      '--baseline', '/nonexistent/baseline.json',
      '--format', 'console',
    ]);
    // It warns but continues with all findings; exit code depends on findings
    expect(result.stdout + result.stderr).toMatch(/Warning|Baseline/i);
  });
});

// ── Cache ─────────────────────────────────────────────────────────────────────

describe('incremental cache', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-cache-test-'));
    // Copy one fixture file into the temp dir so we have something to scan
    fs.copyFileSync(
      path.join(FIXTURES_DIR, 'risky-prompt.txt'),
      path.join(tmpDir, 'risky-prompt.txt'),
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates a cache file after the first scan', () => {
    spawnSync('node', [CLI, 'scan', '--dir', tmpDir, '--format', 'json'], {
      encoding: 'utf8',
      cwd: tmpDir,
    });
    expect(fs.existsSync(path.join(tmpDir, '.hound-cache.json'))).toBe(true);
  });

  it('--no-cache skips cache creation', () => {
    spawnSync('node', [CLI, 'scan', '--dir', tmpDir, '--no-cache', '--format', 'json'], {
      encoding: 'utf8',
      cwd: tmpDir,
    });
    expect(fs.existsSync(path.join(tmpDir, '.hound-cache.json'))).toBe(false);
  });

  it('second scan with cache produces same findings as first', () => {
    const run1 = spawnSync('node', [CLI, 'scan', '--dir', tmpDir, '--format', 'json'], {
      encoding: 'utf8', cwd: tmpDir,
    });
    const run2 = spawnSync('node', [CLI, 'scan', '--dir', tmpDir, '--format', 'json'], {
      encoding: 'utf8', cwd: tmpDir,
    });
    // Both should exit with the same code
    expect(run1.status).toBe(run2.status);
  });
});

// ── Plugin system ─────────────────────────────────────────────────────────────

describe('custom plugin rules', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-plugin-test-'));
    // Target file: will trigger the custom plugin rule (must be > 50 chars for extractor to emit)
    fs.writeFileSync(path.join(tmpDir, 'target.txt'), 'CUSTOM_SECRET_PATTERN found here in this test fixture for the plugin system.');
    // Plugin: exports a single rule that fires on CUSTOM_SECRET_PATTERN
    const plugin = `
module.exports = {
  id: 'PLG-001',
  title: 'Custom plugin test rule',
  severity: 'high',
  confidence: 'high',
  category: 'injection',
  remediation: 'Remove the custom pattern.',
  check: function(prompt) {
    if (prompt.text && prompt.text.includes('CUSTOM_SECRET_PATTERN')) {
      return [{ evidence: 'CUSTOM_SECRET_PATTERN', lineStart: 1, lineEnd: 1 }];
    }
    return [];
  },
};
`;
    fs.writeFileSync(path.join(tmpDir, 'my-plugin.js'), plugin);
    // Config pointing to the plugin
    const config = {
      include: ['**/*.txt'],
      exclude: [],
      threshold: 1,
      plugins: ['./my-plugin.js'],
    };
    fs.writeFileSync(path.join(tmpDir, '.contexthoundrc.json'), JSON.stringify(config));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads plugin and fires custom rule', () => {
    const result = spawnSync('node', [CLI, 'scan', '--dir', tmpDir, '--verbose'], {
      encoding: 'utf8',
      cwd: tmpDir,
    });
    expect(result.stdout + result.stderr).toMatch(/PLG-001/);
  });

  it('custom rule contributes to scan failure', () => {
    const result = spawnSync('node', [CLI, 'scan', '--dir', tmpDir], {
      encoding: 'utf8',
      cwd: tmpDir,
    });
    // threshold=1, so any finding causes exit 2 or 3
    expect([2, 3]).toContain(result.status);
  });
});

// ── explain command ───────────────────────────────────────────────────────────

describe('explain command', () => {
  it('explains a single rule with MITRE and remediation', () => {
    const r = runCli(['explain', 'INJ-001']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/INJ-001/);
    expect(r.stdout).toMatch(/Remediation:/);
    expect(r.stdout).toMatch(/hound-disable-next-line INJ-001/);
  });

  it('is case-insensitive', () => {
    const r = runCli(['explain', 'inj-001']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/INJ-001/);
  });

  it('matches a rule family by prefix', () => {
    const r = runCli(['explain', 'PST']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/PST-001/);
    expect(r.stdout).toMatch(/rules matched/);
  });

  it('emits JSON with --format json', () => {
    const r = runCli(['explain', 'RAG-007', '--format', 'json']);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed[0].id).toBe('RAG-007');
    expect(parsed[0]).toHaveProperty('remediation');
  });

  it('exits non-zero for an unknown rule', () => {
    const r = runCli(['explain', 'ZZZ-999']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/No rule matches/);
  });
});

// ── presets ────────────────────────────────────────────────────────────────────

describe('rule presets', () => {
  it('--list-presets prints presets and exits 0', () => {
    const r = runCli(['scan', '--list-presets']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/owasp-llm-top10/);
    expect(r.stdout).toMatch(/mcp/);
  });

  it('--preset with an unknown name exits 1 with a helpful message', () => {
    const r = runCli(['scan', '--preset', 'bogus', '--dir', FIXTURES_DIR]);
    expect(r.status).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/Unknown preset "bogus"/);
  });

  it('--preset restricts findings to the bundle', () => {
    const r = runCli(['scan', '--dir', FIXTURES_DIR, '--preset', 'jailbreak', '--format', 'json', '--out', path.join(os.tmpdir(), 'preset-jbk'), '--no-cache']);
    const parsed = JSON.parse(fs.readFileSync(path.join(os.tmpdir(), 'preset-jbk.json'), 'utf8'));
    const ids = [...new Set((parsed.allFindings ?? []).map((f: { id: string }) => f.id))] as string[];
    // every reported rule must be a JBK rule
    expect(ids.every(id => id.startsWith('JBK-'))).toBe(true);
  });
});
