import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { resolveDiffRef, getChangedFiles } from '../src/scanner/gitDiff';
import { runScan } from '../src/scanner/pipeline';
import { DEFAULT_CONFIG } from '../src/config/defaults';

describe('resolveDiffRef', () => {
  it('returns null when diff is off', () => {
    expect(resolveDiffRef(undefined)).toBeNull();
    expect(resolveDiffRef(false)).toBeNull();
  });
  it('defaults to origin/main when the flag is given with no value', () => {
    expect(resolveDiffRef(true)).toBe('origin/main');
    expect(resolveDiffRef('')).toBe('origin/main');
  });
  it('passes an explicit ref through', () => {
    expect(resolveDiffRef('HEAD~3')).toBe('HEAD~3');
  });
});

describe('getChangedFiles', () => {
  it('returns null outside a git repository', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-nogit-'));
    try {
      expect(getChangedFiles(tmp, 'HEAD')).toBeNull();
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('--diff mode integration', () => {
  let repo: string;
  const git = (args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' });

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-diff-'));
    git(['init', '-q']);
    git(['config', 'user.email', 't@t.t']);
    git(['config', 'user.name', 'test']);
    // Committed baseline file with a finding (INJ-001 via role/content interpolation)
    fs.writeFileSync(path.join(repo, 'old.ts'), 'const p = { role: "system", content: `You are a bot. Use ${userInput} now` };\n');
    git(['add', '.']);
    git(['commit', '-qm', 'base']);
  });

  afterEach(() => { fs.rmSync(repo, { recursive: true, force: true }); });

  const cfg = (extra = {}) => ({
    ...DEFAULT_CONFIG, include: ['**/*.ts'], exclude: [], cache: false, ...extra,
  });

  it('scans only files changed vs the ref', async () => {
    // New, uncommitted file also has a finding
    fs.writeFileSync(path.join(repo, 'new.ts'), 'const q = { role: "system", content: `You are a bot. Answer ${userInput} now` };\n');

    const full = await runScan(repo, cfg());
    const diff = await runScan(repo, cfg({ diff: 'HEAD' }));

    const fullFiles = full.files.map(f => path.basename(f.file)).sort();
    const diffFiles = diff.files.map(f => path.basename(f.file));

    expect(fullFiles).toEqual(['new.ts', 'old.ts']);
    expect(diffFiles).toEqual(['new.ts']); // old.ts unchanged vs HEAD
  });

  it('falls back to scanning all when the ref is invalid', async () => {
    const result = await runScan(repo, cfg({ diff: 'does-not-exist-ref' }));
    expect(result.files.length).toBeGreaterThan(0); // didn't silently scan nothing
  });
});
