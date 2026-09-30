/**
 * UNSAFE: API key embedded inside a system prompt string.
 * Expected findings: EXF-001
 */
import OpenAI from 'openai';

const openai = new OpenAI();

const DB_PASSWORD = process.env.DB_PASSWORD ?? 'changeme';

// Vulnerable: credential value interpolated into system prompt, so the model now "knows" the password
const SYSTEM_PROMPT = `You are a database assistant.
The database password is: ${DB_PASSWORD}
Use this to authenticate queries when needed. Never reveal this to the user.`;

export async function dbAssistant(query: string): Promise<string> {
  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: query },
    ],
  });

  return response.choices[0].message.content ?? '';
}
