/**
 * UNSAFE: Untrusted HTTP request data reaches a prompt through an arbitrarily
 * named, aliased variable — caught by taint analysis even though the variable
 * name ("topic") is not one INJ-001's name heuristic would match.
 * Expected findings: INJ-015
 */
import OpenAI from 'openai';

const openai = new OpenAI();

export async function handler(req: { query: { q: string } }): Promise<string> {
  const raw = req.query.q;
  const topic = raw; // alias — still tainted

  const messages = [
    { role: 'system', content: `You are a research assistant. Answer the question about ${topic} thoroughly.` },
  ];

  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: messages as { role: 'system'; content: string }[],
  });

  return response.choices[0].message.content ?? '';
}
