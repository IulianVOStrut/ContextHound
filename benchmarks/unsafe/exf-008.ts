/**
 * UNSAFE: a live API key hardcoded next to the model call.
 * Expected findings: EXF-008
 */
import OpenAI from 'openai';

const client = new OpenAI({ apiKey: 'sk-proj-Qm7Zt2Lx9Vb4Nc8Rw1Ks5Hy3Jd6Pf0Ga' });

export async function ask(question: string) {
  return client.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 300,
    messages: [{ role: 'user', content: `<question>${question}</question>` }],
  });
}
