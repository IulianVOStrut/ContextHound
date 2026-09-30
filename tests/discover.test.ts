import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { discoverFiles } from '../src/scanner/discover';
import { DEFAULT_CONFIG } from '../src/config/defaults';
import type { AuditConfig } from '../src/types';

function write(root: string, rel: string, content = 'x\n'): void {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

async function found(root: string, extra: Partial<AuditConfig> = {}): Promise<string[]> {
  const cfg: AuditConfig = { ...DEFAULT_CONFIG, include: ['**/*.ts', '**/*.md'], exclude: [], ...extra };
  return (await discoverFiles(root, cfg)).map(f => path.relative(root, f).split(path.sep).join('/'));
}

describe('discoverFiles: .gitignore', () => {
  let repo: string;
  const git = (args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' });

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-discover-'));
    git(['init', '-q']);
    git(['config', 'user.email', 't@t.t']);
    git(['config', 'user.name', 'test']);
  });
  afterEach(() => { fs.rmSync(repo, { recursive: true, force: true }); });

  it('skips files ignored by root and nested .gitignore files', async () => {
    write(repo, '.gitignore', 'generated/\n*.local.md\n');
    write(repo, 'pkg/.gitignore', 'fixtures.ts\n');
    write(repo, 'src/a.ts');
    write(repo, 'generated/b.ts');
    write(repo, 'notes.local.md');
    write(repo, 'pkg/fixtures.ts');
    write(repo, 'pkg/keep.ts');
    expect(await found(repo)).toEqual(['pkg/keep.ts', 'src/a.ts']);
  });

  it('still scans tracked files that match .gitignore', async () => {
    write(repo, 'vendor/tracked.ts');
    git(['add', 'vendor/tracked.ts']);
    git(['commit', '-qm', 'add']);
    write(repo, '.gitignore', 'vendor/\n');
    write(repo, 'vendor/untracked.ts');
    expect(await found(repo)).toEqual(['vendor/tracked.ts']);
  });

  it('scans ignored files with gitignore: false', async () => {
    write(repo, '.gitignore', 'generated/\n');
    write(repo, 'generated/b.ts');
    expect(await found(repo, { gitignore: false })).toEqual(['generated/b.ts']);
  });

  it('applies .git/info/exclude', async () => {
    write(repo, '.git/info/exclude', 'scratch.ts\n');
    write(repo, 'scratch.ts');
    write(repo, 'real.ts');
    expect(await found(repo)).toEqual(['real.ts']);
  });
});

describe('discoverFiles outside git', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-nogit-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('falls back to the scan directory .gitignore', async () => {
    write(dir, '.gitignore', 'out/\n');
    write(dir, 'out/a.ts');
    write(dir, 'b.ts');
    expect(await found(dir)).toEqual(['b.ts']);
  });
});

describe('discoverFiles: .houndignore', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-houndignore-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('uses gitignore syntax: directories, basenames anywhere and negation', async () => {
    write(dir, '.houndignore', '# comment\nsecrets/\n*.test.ts\n!keep.test.ts\n');
    write(dir, 'secrets/key.ts');
    write(dir, 'src/deep/a.test.ts');
    write(dir, 'src/keep.test.ts');
    write(dir, 'src/main.ts');
    expect(await found(dir)).toEqual(['src/keep.test.ts', 'src/main.ts']);
  });

  it('still honours glob patterns written for the old behaviour', async () => {
    write(dir, '.houndignore', 'src/generated/**\n');
    write(dir, 'src/generated/x.ts');
    write(dir, 'src/y.ts');
    expect(await found(dir)).toEqual(['src/y.ts']);
  });

  it('applies even with gitignore: false', async () => {
    write(dir, '.houndignore', 'skip.ts\n');
    write(dir, 'skip.ts');
    write(dir, 'scan.ts');
    expect(await found(dir, { gitignore: false })).toEqual(['scan.ts']);
  });
});
