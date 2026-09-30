import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { allRules } from '../src/rules/index';
import type { Rule } from '../src/rules/types';

const { updateReadme, renderRules, FAMILIES } = require('../scripts/readme-rules.js') as {
  updateReadme: (readme: string, rules: readonly Rule[]) => string;
  renderRules: (rules: readonly Rule[]) => string;
  FAMILIES: [string, string, string][];
};

const root = path.resolve(__dirname, '..');

describe('README rule tables', () => {
  it('are up to date with the rule registry (run `npm run docs`)', () => {
    const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
    expect(updateReadme(readme, allRules)).toBe(readme);
  });

  it('list every built-in rule exactly once', () => {
    const block = renderRules(allRules);
    for (const rule of allRules) {
      expect(block.split(`| ${rule.id} |`).length - 1).toBe(1);
    }
  });

  it('cover every rule prefix', () => {
    const prefixes = new Set(FAMILIES.map(([prefix]) => prefix));
    for (const rule of allRules) expect(prefixes).toContain(rule.id.split('-')[0]);
  });

  it('reject a rule from an undocumented family', () => {
    const stray = { ...allRules[0], id: 'ZZZ-001' } as Rule;
    expect(() => renderRules([stray])).toThrow(/ZZZ/);
  });
});

describe('repository text', () => {
  it('uses no em or en dashes (write a colon, comma, parentheses or "to" instead)', () => {
    const files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' })
      .split('\0')
      .filter(Boolean);
    const offenders: string[] = [];
    for (const file of files) {
      const abs = path.join(root, file);
      if (!fs.existsSync(abs)) continue;
      const buf = fs.readFileSync(abs);
      if (buf.includes(0)) continue; // binary
      buf.toString('utf8').split('\n').forEach((line, i) => {
        if (/[\u2013\u2014]/.test(line)) offenders.push(`${file}:${i + 1}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});
