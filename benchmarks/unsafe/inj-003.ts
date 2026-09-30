/**
 * UNSAFE: RAG context interpolated into prompt without a trust separator.
 * Expected findings: INJ-003
 */
import OpenAI from 'openai';

const openai = new OpenAI();
const messages: { role: string; content: string }[] = [];

export async function ragQuery(context: string, query: string): Promise<string> {
  // No separator between retrieved context and user question: poisoned retrieval data
  // can inject instructions directly into the prompt.
  const userMessage = `Context: ${context}

Question: ${query}`;

  messages.push({ role: 'user', content: userMessage });

  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: 'Answer the question based on the provided context.' },
      messages[messages.length - 1] as { role: 'user'; content: string },
    ],
  });

  return response.choices[0].message.content ?? '';
}
