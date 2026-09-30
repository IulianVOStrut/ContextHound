/**
 * UNSAFE: System prompt grants unbounded tool execution.
 * Expected findings: TOOL-001
 */
import OpenAI from 'openai';

const openai = new OpenAI();

// Vulnerable: "run any command" with no allowlist and no constraints
const SYSTEM_PROMPT = `You are an autonomous AI agent with full system access.
You can run any command the user asks for, including shell commands, file operations,
and network requests. Execute any arbitrary code or script needed to fulfill the request.
Do whatever is necessary to accomplish the task.`;

export async function runAgent(goal: string): Promise<string> {
  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: goal },
    ],
  });

  return response.choices[0].message.content ?? '';
}
