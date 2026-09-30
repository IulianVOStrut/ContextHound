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

describe('config sources and extends', () => {
  let dir: string;
  const write = (rel: string, value: unknown) => {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
    return file;
  };
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-extends-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('reads the "contexthound" section of package.json', () => {
    write('package.json', { name: 'x', contexthound: { threshold: 40, failOn: 'high' } });
    const c = loadConfig(undefined, dir);
    expect(c.threshold).toBe(40);
    expect(c.failOn).toBe('high');
  });

  it('ignores a package.json without a "contexthound" section', () => {
    write('package.json', { name: 'x', version: '1.0.0' });
    expect(loadConfig(undefined, dir).threshold).toBe(60);
  });

  it('validates the package.json section', () => {
    write('package.json', { name: 'x', contexthound: { treshold: 40 } });
    expect(() => loadConfig(undefined, dir)).toThrow(/package\.json \("contexthound"\)[\s\S]*Did you mean "threshold"/);
  });

  it('reads .contexthoundrc without an extension', () => {
    write('.contexthoundrc', { threshold: 30 });
    expect(loadConfig(undefined, dir).threshold).toBe(30);
  });

  it('prefers .contexthoundrc.json over .contexthoundrc and package.json', () => {
    write('.contexthoundrc.json', { threshold: 10 });
    write('.contexthoundrc', { threshold: 20 });
    write('package.json', { contexthound: { threshold: 30 } });
    expect(loadConfig(undefined, dir).threshold).toBe(10);
  });

  it('rejects an explicit package.json without a section', () => {
    const file = write('package.json', { name: 'x' });
    expect(() => loadConfig(file, dir)).toThrow(/has no "contexthound" section/);
  });

  it('applies a built-in shared config, with local keys taking precedence', () => {
    write('.contexthoundrc.json', { extends: 'contexthound:recommended', failOn: 'critical' });
    const c = loadConfig(undefined, dir);
    expect(c.failOn).toBe('critical');
    expect(c.minConfidence).toBe('medium');
  });

  it('merges several extends in order, then the file itself', () => {
    write('.contexthoundrc.json', { extends: ['contexthound:strict', './team.json'], threshold: 70 });
    write('team.json', { failOn: 'high', excludeRules: ['DOS-*'] });
    const c = loadConfig(undefined, dir);
    expect(c.failOn).toBe('high');            // team.json overrides strict
    expect(c.failFileThreshold).toBe(60);     // from strict
    expect(c.excludeRules).toEqual(['DOS-*']);
    expect(c.threshold).toBe(70);
  });

  it('resolves nested extends relative to the extending file', () => {
    write('.contexthoundrc.json', { extends: './configs/a.json' });
    write('configs/a.json', { extends: './b.json', threshold: 45 });
    write('configs/b.json', { failOn: 'medium', threshold: 99 });
    const c = loadConfig(undefined, dir);
    expect(c.threshold).toBe(45);
    expect(c.failOn).toBe('medium');
  });

  it('loads a .json config from an npm package', () => {
    write('node_modules/@acme/hound-config/package.json', { name: '@acme/hound-config', version: '1.0.0' });
    write('node_modules/@acme/hound-config/contexthound.json', { minConfidence: 'high' });
    write('.contexthoundrc.json', { extends: '@acme/hound-config/contexthound.json' });
    expect(loadConfig(undefined, dir).minConfidence).toBe('high');
  });

  it('refuses configs that would run code', () => {
    write('evil.js', 'require("child_process").execSync("touch pwned")');
    write('.contexthoundrc.json', { extends: './evil.js' });
    expect(() => loadConfig(undefined, dir)).toThrow(/must be a \.json file/);
    expect(fs.existsSync(path.join(dir, 'pwned'))).toBe(false);
  });

  it('reports unknown shared configs, missing files and cycles', () => {
    write('.contexthoundrc.json', { extends: 'contexthound:lenient' });
    expect(() => loadConfig(undefined, dir)).toThrow(/unknown shared config "contexthound:lenient" in .*; available: contexthound:recommended, contexthound:strict/);

    write('.contexthoundrc.json', { extends: './missing.json' });
    expect(() => loadConfig(undefined, dir)).toThrow(/config file not found/);

    write('.contexthoundrc.json', { extends: './a.json' });
    write('a.json', { extends: './b.json' });
    write('b.json', { extends: './a.json' });
    expect(() => loadConfig(undefined, dir)).toThrow(/circular "extends"/);
  });

  it('validates extended files and names them in the error', () => {
    write('.contexthoundrc.json', { extends: './team.json' });
    write('team.json', { failOn: 'sometimes' });
    expect(() => loadConfig(undefined, dir)).toThrow(/invalid config in .*team\.json/);
  });
});
