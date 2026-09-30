import fs from 'fs';
import os from 'os';
import path from 'path';
import { buildPrComment, PR_COMMENT_MARKER } from '../src/report/prComment';
import type { Finding, ScanResult } from '../src/types';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const script = require('../scripts/action-pr-comment.js') as {
  run(env: Record<string, string>): Promise<string>;
  BOT_LOGIN: string;
};

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'INJ-001', title: 'Direct user input concatenation without delimiter', severity: 'high', confidence: 'medium',
    evidence: 'const p = `You are ${userInput}`', file: 'src/chat.ts', lineStart: 12, lineEnd: 12,
    remediation: 'Wrap input.', riskPoints: 20, ...overrides,
  };
}

function result(findings: Finding[], passed = true): ScanResult {
  return {
    repoScore: findings.length ? 40 : 0, scoreLabel: 'medium', threshold: 60, passed,
    files: findings.length ? [{ file: 'src/chat.ts', findings, fileScore: 40 }] : [], allFindings: findings,
  };
}

describe('buildPrComment', () => {
  it('starts with the marker and summarises a clean scan', () => {
    const body = buildPrComment(result([]));
    expect(body.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(body).toContain('ContextHound: Passed');
    expect(body).toContain('No findings.');
  });

  it('lists findings worst first with links to the head commit', () => {
    const body = buildPrComment(result([
      finding({ severity: 'medium', id: 'RAG-001', lineStart: 3 }),
      finding({ severity: 'critical', id: 'EXF-008', file: 'src/a b.ts', lineStart: 7 }),
    ], false), { blobBaseUrl: 'https://github.com/o/r/blob/abc123', diffRef: 'origin/main' });
    expect(body).toContain('ContextHound: Failed');
    expect(body).toContain('in files changed since `origin/main`');
    expect(body.indexOf('EXF-008')).toBeLessThan(body.indexOf('RAG-001'));
    expect(body).toContain('(https://github.com/o/r/blob/abc123/src/a%20b.ts#L7)');
    expect(body).toContain('critical: 1 · high: 0 · medium: 1 · low: 0');
  });

  it('keeps scanned content from injecting Markdown, HTML, links or mentions', () => {
    const body = buildPrComment(result([finding({
      file: 'x|y @admin <img src=x onerror=alert(1)>.ts',
      evidence: '](http://evil) <script>alert(1)</script> @everyone `',
    })]));
    const table = body.split('\n').find(l => l.startsWith('| high'))!;
    expect(table.split(/(?<!\\)\|/).length).toBe(6); // the pipe in the path did not add a column
    // Every untrusted value sits inside a code span, so none of it is live.
    const risky = /@admin|@everyone|<img|<script|\]\(http:\/\/evil/;
    for (const line of body.split('\n').filter(l => risky.test(l))) {
      const outsideCode = line.replace(/(`+)[\s\S]*?\1/g, '');
      expect(outsideCode).not.toMatch(risky);
    }
  });

  it('renders failure messages, which can quote file paths, as code', () => {
    const r = result([finding()], false);
    r.failures = [{ kind: 'file-threshold', message: 'File x/@admin <img src=x>.ts scored 90' }];
    const line = buildPrComment(r).split('\n').find(l => l.includes('@admin'))!;
    expect(line.replace(/(`+)[\s\S]*?\1/g, '')).not.toMatch(/@admin|<img/);
  });

  it('caps the table and says how many were left out', () => {
    const many = Array.from({ length: 60 }, (_, i) => finding({ lineStart: i + 1 }));
    const body = buildPrComment(result(many), { maxRows: 50 });
    expect(body.split('\n').filter(l => l.startsWith('| high')).length).toBe(50);
    expect(body).toContain('10 more finding(s) not shown');
  });
});

describe('action-pr-comment script', () => {
  let dir: string;
  const calls: { method: string; url: string; body?: { body: string } }[] = [];
  let existing: unknown[] = [];
  const realFetch = global.fetch;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hound-comment-'));
    calls.length = 0;
    existing = [];
    // A fake installed package that re-exports the library under test.
    const pkg = path.join(dir, 'node_modules', 'context-hound');
    fs.mkdirSync(pkg, { recursive: true });
    fs.writeFileSync(path.join(pkg, 'index.js'), `module.exports = require(${JSON.stringify(path.resolve(__dirname, '../src/report/prComment.ts'))});`);
    fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(result([finding()])));
    fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify({ pull_request: { number: 7, head: { sha: 'abc' } } }));
    global.fetch = (async (url: string, init: { method: string; body?: string }) => {
      calls.push({ method: init.method, url: String(url), body: init.body ? JSON.parse(init.body) : undefined });
      const payload = init.method === 'GET' ? existing : {};
      return { ok: true, status: 200, statusText: 'OK', json: async () => payload };
    }) as unknown as typeof fetch;
  });
  afterEach(() => {
    global.fetch = realFetch;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const env = () => ({
    GITHUB_EVENT_PATH: path.join(dir, 'event.json'), GITHUB_REPOSITORY: 'o/r', GITHUB_TOKEN: 't',
    GITHUB_API_URL: 'https://api.github.com', HOUND_PKG: dir, HOUND_RESULTS: path.join(dir, 'results.json'),
  });

  it('creates a comment when none exists', async () => {
    expect(await script.run(env())).toBe('created');
    const post = calls.find(c => c.method === 'POST')!;
    expect(post.url).toBe('https://api.github.com/repos/o/r/issues/7/comments');
    expect(post.body!.body.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(post.body!.body).toContain('https://github.com/o/r/blob/abc/src/chat.ts#L12');
  });

  it('updates its own comment in place', async () => {
    existing = [{ id: 99, user: { login: script.BOT_LOGIN }, body: `${PR_COMMENT_MARKER}\nold` }];
    expect(await script.run(env())).toBe('updated');
    expect(calls.find(c => c.method === 'PATCH')!.url).toBe('https://api.github.com/repos/o/r/issues/comments/99');
    expect(calls.some(c => c.method === 'POST')).toBe(false);
  });

  it('never edits a look-alike comment written by someone else', async () => {
    existing = [{ id: 5, user: { login: 'mallory' }, body: `${PR_COMMENT_MARKER}\nfake` }];
    expect(await script.run(env())).toBe('created');
    expect(calls.some(c => c.method === 'PATCH')).toBe(false);
  });

  it('skips events without a pull request', async () => {
    fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify({ ref: 'refs/heads/main' }));
    expect(await script.run(env())).toBe('skipped');
    expect(calls).toHaveLength(0);
  });
});
