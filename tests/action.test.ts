import fs from 'fs';
import path from 'path';

// Guards for the composite GitHub Action in action.yml.

const ROOT = path.resolve(__dirname, '..');
const action = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8');
const lines = action.split('\n');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as { version: string };

describe('action.yml', () => {
  it('lives at the repository root so `uses: IulianVOStrut/ContextHound@v2` resolves', () => {
    expect(fs.existsSync(path.join(ROOT, '.github', 'action.yml'))).toBe(false);
  });

  it('defaults to the tool version released alongside it', () => {
    const m = action.match(/\n  version:\n(?:    .*\n)*?    default: '([^']+)'/);
    expect(m?.[1]).toBe(pkg.version);
  });

  it('never interpolates inputs or expressions into run scripts', () => {
    // Expressions are only allowed as env/with values, if: conditions and
    // output values; inside run: they would be template-injected into bash.
    let inRun = false;
    let runIndent = 0;
    const offenders: string[] = [];
    lines.forEach((line, i) => {
      const indent = line.length - line.trimStart().length;
      if (/^\s+run: \|/.test(line)) { inRun = true; runIndent = indent; return; }
      if (inRun && line.trim() !== '' && indent <= runIndent) inRun = false;
      if (inRun && line.includes('${{')) offenders.push(`${i + 1}: ${line.trim()}`);
    });
    expect(offenders).toEqual([]);
  });

  it('pins every third-party action to a full commit SHA', () => {
    const uses = lines.filter(l => /^\s+uses: /.test(l)).map(l => l.trim());
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/^uses: [\w.-]+\/[\w./-]+@[0-9a-f]{40} # v\d/);
  });

  it('installs the pinned package by exact name, not a bare `npx hound`', () => {
    expect(action).toContain('"context-hound@$VERSION"');
    expect(action).not.toMatch(/npx\s+hound/);
    expect(action).not.toMatch(/npm ci/);
  });
});
