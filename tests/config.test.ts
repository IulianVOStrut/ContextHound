import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { loadConfig, ConfigError } from '../src/config/loader';
import { validateConfigObject, buildJsonSchema, CONFIG_FIELDS } from '../src/config/schema';

const CLI = path.resolve(__dirname, '../dist/cli.js');

function withConfig(content: string, fn: (dir: string, file: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-config-'));
  const file = path.join(dir, '.contexthoundrc.json');
  fs.writeFileSync(file, content);
  try { fn(dir, file); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

describe('validateConfigObject', () => {
  it('accepts a full valid config, nulls for optional gates, $schema and _comment keys', () => {
    expect(validateConfigObject({
      $schema: 'x', _comment: 'y',
      include: ['**/*.ts'], exclude: [], threshold: 60, formats: ['console', 'sarif'], out: 'r',
      maxFindings: null, maxFileSize: 0, failOn: null, verbose: false, excludeRules: ['CMD-*'],
      includeRules: [], minConfidence: 'medium', failFileThreshold: null, concurrency: 8, cache: true,
      baseline: 'b.json', plugins: [], diff: true, reportUnusedSuppressions: false,
    })).toEqual([]);
  });

  it('rejects typos with a suggestion', () => {
    expect(validateConfigObject({ failon: 'high' })).toEqual(['unknown option "failon". Did you mean "failOn"?']);
    expect(validateConfigObject({ treshold: 50 })[0]).toContain('Did you mean "threshold"?');
  });

  it('rejects wrong types and out-of-range values', () => {
    const problems = validateConfigObject({
      threshold: '60', failOn: 'hgih', formats: ['console', 'pdf'], concurrency: 0, include: 'src/**', cache: 'no',
    });
    expect(problems).toEqual(expect.arrayContaining([
      '"threshold" must be a whole number, got "60"',
      '"failOn" must be one of critical, high, medium, got "hgih"',
      expect.stringContaining('"formats" has unknown value(s) "pdf"'),
      '"concurrency" must be between 1 and 256, got 0',
      '"include" must be an array of strings, got "src/**"',
      '"cache" must be true or false, got "no"',
    ]));
    expect(validateConfigObject({ threshold: 101 })).toEqual(['"threshold" must be between 0 and 100, got 101']);
  });

  it('rejects a non-object config', () => {
    expect(validateConfigObject([1, 2])).toEqual(['the config file must contain a JSON object']);
  });
});

describe('loadConfig', () => {
  const saved = { ...process.env };
  afterEach(() => { process.env = { ...saved }; });

  it('throws on invalid JSON instead of silently using defaults', () => {
    withConfig('{ "threshold": 60, }', dir => {
      expect(() => loadConfig(undefined, dir)).toThrow(ConfigError);
      expect(() => loadConfig(undefined, dir)).toThrow(/could not parse/);
    });
  });

  it('throws when an explicit --config path does not exist', () => {
    expect(() => loadConfig('/nonexistent/rc.json')).toThrow(/config file not found/);
  });

  it('treats a missing default config file as "use defaults"', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-config-'));
    expect(loadConfig(undefined, dir).threshold).toBe(60);
  });

  it('reads diff and reportUnusedSuppressions from the file', () => {
    withConfig('{ "diff": true, "reportUnusedSuppressions": true }', dir => {
      const c = loadConfig(undefined, dir);
      expect(c.diff).toBe('origin/main');
      expect(c.reportUnusedSuppressions).toBe(true);
    });
  });

  it('treats null gates from hound init as unset', () => {
    withConfig('{ "failOn": null, "maxFindings": null, "minConfidence": null }', dir => {
      const c = loadConfig(undefined, dir);
      expect(c.failOn).toBeUndefined();
      expect(c.maxFindings).toBeUndefined();
    });
  });

  it('validates environment variable overrides', () => {
    process.env.HOUND_FAIL_ON = 'hgih';
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-config-'));
    expect(() => loadConfig(undefined, dir)).toThrow('HOUND_FAIL_ON must be one of critical, high, medium, got "hgih"');
    process.env.HOUND_FAIL_ON = '';
    process.env.HOUND_THRESHOLD = '60abc';
    expect(() => loadConfig(undefined, dir)).toThrow('HOUND_THRESHOLD must be a whole number, got "60abc"');
  });
});

describe('CLI option validation', () => {
  const run = (args: string[]) => spawnSync('node', [CLI, ...args], { encoding: 'utf8' });

  it.each([
    [['--threshold', 'abc'], '--threshold must be a whole number'],
    [['--threshold', '150'], '--threshold must be between 0 and 100'],
    [['--fail-on', 'hgih'], '--fail-on must be one of critical, high, medium'],
    [['--min-confidence', 'max'], '--min-confidence must be one of low, medium, high'],
    [['--format', 'console,pdf'], '--format must be one of'],
    [['--concurrency', '0'], '--concurrency must be between 1 and 256'],
    [['--max-file-size', '-1'], '--max-file-size must be 0 or more'],
  ])('rejects %j', (args, message) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-config-'));
    const r = run(['scan', '--dir', dir, '--no-cache', ...args]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(message);
  });

  it('reports every problem in an invalid config file and exits 1', () => {
    withConfig('{ "failon": "high", "threshold": "60" }', (dir, file) => {
      const r = run(['scan', '--dir', dir, '--config', file]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('unknown option "failon". Did you mean "failOn"?');
      expect(r.stderr).toContain('"threshold" must be a whole number');
    });
  });
});

describe('JSON Schema', () => {
  it('committed schema/contexthoundrc.schema.json is up to date (run `npm run schema`)', () => {
    const committed = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../schema/contexthoundrc.schema.json'), 'utf8'));
    expect(committed).toEqual(buildJsonSchema());
  });

  it('covers every config field', () => {
    const props = (buildJsonSchema().properties as Record<string, unknown>);
    for (const key of Object.keys(CONFIG_FIELDS)) expect(props).toHaveProperty(key);
  });

  it('hound init output and the repository config both validate', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-config-'));
    spawnSync('node', [CLI, 'init'], { cwd: dir, encoding: 'utf8' });
    const generated = JSON.parse(fs.readFileSync(path.join(dir, '.contexthoundrc.json'), 'utf8'));
    expect(validateConfigObject(generated)).toEqual([]);
    expect(generated.$schema).toContain('contexthoundrc.schema.json');
    const repo = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../.contexthoundrc.json'), 'utf8'));
    expect(validateConfigObject(repo)).toEqual([]);
  });
});
