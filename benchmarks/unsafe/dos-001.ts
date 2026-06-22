/**
 * UNSAFE: Reasoning-inflation / ThinkTrap. The completion sets no output cap and
 * the prompt explicitly instructs the model to produce unbounded output, letting
 * an attacker drive runaway token generation and cost.
 * Expected findings: DOS-001
 */
import OpenAI from 'openai';

const openai = new OpenAI();

export async function deepDive(question: string): Promise<string> {
  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      {
        role: 'user',
        content:
          'Think step by step and be as exhaustive as possible. ' +
          'Do not summarize or stop early — explain every detail in full detail: ' +
          question,
      },
    ],
  });

  return response.choices[0].message.content ?? '';
}
