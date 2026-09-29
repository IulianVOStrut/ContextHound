/**
 * UNSAFE: retrieved documents placed in the system role.
 * Expected findings: RAG-001
 */
import OpenAI from 'openai';

const client = new OpenAI();

export async function answer(question: string, retrievedDocs: string[]) {
  return client.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 400,
    messages: [
      { role: 'system', content: retrievedDocs.join('\n') },
      { role: 'user', content: `<q>${question}</q>` },
    ],
  });
}
