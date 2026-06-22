import { taintRules } from '../src/rules/taint';
import type { ExtractedPrompt } from '../src/scanner/extractor';

const rule = taintRules.find(r => r.id === 'INJ-015')!;

function codeBlock(text: string): ExtractedPrompt {
  return { text, lineStart: 1, lineEnd: text.split('\n').length, kind: 'code-block' };
}

function run(src: string) {
  return rule.check(codeBlock(src), 'f.ts');
}

describe('INJ-015 taint analysis', () => {
  it('flags an untrusted request field flowing into a prompt', () => {
    const src = [
      'const q = req.query.q;',
      'const messages = [{ role: "system", content: `You are a bot. Answer ${q} now` }];',
    ].join('\n');
    const m = run(src);
    expect(m).toHaveLength(1);
    expect(m[0].lineStart).toBe(2);
  });

  it('follows a one-hop alias', () => {
    const src = [
      'const raw = req.body.topic;',
      'const topic = raw;',
      'const p = `You are an assistant. Summarise ${topic} for the user.`;',
    ].join('\n');
    expect(run(src)).toHaveLength(1);
  });

  it('flags destructured request fields', () => {
    const src = [
      'const { question } = req.body;',
      'const p = `System: answer the prompt ${question} carefully`;',
    ].join('\n');
    expect(run(src)).toHaveLength(1);
  });

  it('does not flag a sanitised value', () => {
    const src = [
      'const q = sanitize(req.query.q);',
      'const p = `You are a bot. Answer ${q} now`;',
    ].join('\n');
    expect(run(src)).toHaveLength(0);
  });

  it('does not flag when there is no untrusted source', () => {
    const src = [
      'const q = config.defaultTopic;',
      'const p = `You are a bot. Answer ${q} now`;',
    ].join('\n');
    expect(run(src)).toHaveLength(0);
  });

  it('does not flag a tainted value in a non-prompt template', () => {
    const src = [
      'const id = req.params.id;',
      'const sql = `SELECT * FROM users WHERE id = ${id}`;',
    ].join('\n');
    expect(run(src)).toHaveLength(0);
  });

  it('skips names already covered by INJ-001 to avoid double-reporting', () => {
    const src = [
      'const userInput = req.query.q;',
      'const p = `You are a bot. Answer ${userInput} now`;',
    ].join('\n');
    expect(run(src)).toHaveLength(0);
  });

  it('only runs on whole-file code-block prompts', () => {
    const tpl: ExtractedPrompt = {
      text: 'You are a bot. Answer ${q} now', lineStart: 5, lineEnd: 5, kind: 'template-string',
    };
    expect(rule.check(tpl, 'f.ts')).toHaveLength(0);
  });
});
