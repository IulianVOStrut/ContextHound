/**
 * UNSAFE: Direct user input interpolated into template string without delimiter.
 * Expected findings: INJ-001
 */
import OpenAI from 'openai';

const openai = new OpenAI();
const messages: { role: string; content: string }[] = [];

export async function askAssistant(userInput: string): Promise<string> {
  // No boundary label: attacker controls the prompt via the variable
  const prompt = `You must answer the following question as helpfully as possible: ${userInput}`;

  messages.push({ role: 'user', content: prompt });

  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: messages as { role: 'user'; content: string }[],
  });

  return response.choices[0].message.content ?? '';
}
