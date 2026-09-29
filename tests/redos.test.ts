import { allRules } from '../src/rules/index';
import { scoreMitigations } from '../src/rules/mitigation';
import { extractPrompts } from '../src/scanner/extractor';
import type { ExtractedPrompt } from '../src/scanner/extractor';

// Regression guard against super-linear regexes. Scanned files are untrusted
// (a pull request can add any content), so a rule that backtracks
// quadratically or worse lets a single file stall CI.
//
// Each input is ~100k characters. A linear rule handles that in a few
// milliseconds; the quadratic patterns this suite was written against took
// 1 to 10 seconds, and the cubic INJ-006 pattern over a minute. The budget
// leaves a wide margin for slow CI runners.

const SIZE = 100_000;
const BUDGET_MS = 750;

// Tokens that triggered pathological backtracking in fuzzing, plus generic ones.
const TOKENS = [
  ' ', 'ab', '> ', 'wget ', 'http://', '${', 'f"', '<!-- ignore ', '`', '{',
  'user: ', '"content": "', 'role: "system", content: x ', '${input} ',
];

type Shape = 'line' | 'lines';

function makeText(token: string, shape: Shape): string {
  const reps = Math.ceil(SIZE / token.length);
  return shape === 'line' ? token.repeat(reps) : Array(Math.min(reps, 20_000)).fill(token).join('\n');
}

const COMBOS: Array<{ kind: ExtractedPrompt['kind']; file: string }> = [
  { kind: 'raw', file: 'SKILL.md' },
  { kind: 'code-block', file: 'agent.ts' },
  { kind: 'code-block', file: 'agent.py' },
  { kind: 'object-field', file: 'package.json' },
];

describe('rules run in linear time on pathological input', () => {
  for (const token of TOKENS) {
    for (const shape of ['line', 'lines'] as Shape[]) {
      it(`token ${JSON.stringify(token)} as ${shape}`, () => {
        const text = makeText(token, shape);
        const lineEnd = text.split('\n').length;
        const slow: string[] = [];
        for (const { kind, file } of COMBOS) {
          const prompt: ExtractedPrompt = { text, lineStart: 1, lineEnd, kind };
          for (const rule of allRules) {
            const t0 = Date.now();
            rule.check(prompt, file);
            const ms = Date.now() - t0;
            if (ms > BUDGET_MS) slow.push(`${rule.id} (${kind}, ${file}): ${ms}ms`);
          }
          const t0 = Date.now();
          scoreMitigations(prompt);
          const ms = Date.now() - t0;
          if (ms > BUDGET_MS) slow.push(`mitigations (${kind}): ${ms}ms`);
        }
        expect(slow).toEqual([]);
      });
    }
  }

  it('prompt extraction is linear on long lines and many lines', () => {
    for (const token of TOKENS) {
      for (const shape of ['line', 'lines'] as Shape[]) {
        const text = makeText(token, shape);
        for (const file of ['a.ts', 'a.py', 'a.md', 'a.json', 'a.yaml', 'SKILL.md']) {
          const t0 = Date.now();
          extractPrompts(file, text);
          expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
        }
      }
    }
  });
});

describe('rules never throw on hostile identifiers', () => {
  // INJ-001 and INJ-007 build RegExps from variable names found in scanned
  // text; unescaped, these crashed the whole scan.
  const hostile = [
    'const p = `You are a bot.\n${foo(} ${input}\n`;',
    'const p = `Answer\n${a[} ${userInput}\n`;',
    'const q = `\n```${a[}```\n`;',
    'const q = `\n```${(a+)+$}```\n`;',
  ];
  for (const text of hostile) {
    it(JSON.stringify(text.slice(0, 40)), () => {
      const lines = text.split('\n').length;
      for (const kind of ['template-string', 'code-block', 'raw'] as const) {
        for (const rule of allRules) {
          expect(() => rule.check({ text, lineStart: 1, lineEnd: lines, kind }, 'x.ts')).not.toThrow();
        }
      }
    });
  }
});
