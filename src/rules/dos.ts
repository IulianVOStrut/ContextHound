import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const dosRules: Rule[] = [
  {
    id: 'DOS-001',
    title: 'Unbounded LLM completion — reasoning-inflation / ThinkTrap risk',
    severity: 'medium',
    confidence: 'medium',
    category: 'dos',
    mitre: 'T1499',
    remediation:
      'This completion call sets no output cap and either uses a reasoning model or contains output-inflating instructions (e.g. "think step by step", "be exhaustive", "in full detail"). An attacker can exploit this via ThinkTrap / reasoning-inflation to force arbitrarily long, expensive generations. Always set max_tokens (OpenAI), max_completion_tokens, max_output_tokens, or max_new_tokens, and cap reasoning effort.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const lines = prompt.text.split('\n');
      const results: RuleMatch[] = [];

      // Patterns that open an LLM completion call block
      const callPattern =
        /\.(?:chat\.completions|completions)\.create\s*\(\s*\{|\.messages\.create\s*\(\s*\{|(?:ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|AzureChatOpenAI)\s*\(/i;

      // Any token-limit parameter
      const limitPattern =
        /max_tokens|max_new_tokens|max_completion_tokens|maxTokens|max_output_tokens|maxOutputTokens/i;

      // A missing cap is only a DoS lever when something can drive the output
      // long. Require a reasoning model (emits unbounded reasoning tokens) or an
      // explicit output-inflation instruction in the prompt — the actual
      // ThinkTrap vector — rather than flagging every uncapped call.
      const reasoningModel =
        /\bo[1-4](?:-(?:mini|preview|pro))?\b|reasoning_effort|extended[\s_]thinking|thinking\s*[:=]/i;
      const inflationPrompt =
        /step[-\s]?by[-\s]?step|chain[-\s]?of[-\s]?thought|as\s+(?:much|many)\s+\w+\s+as\s+(?:possible|you\s+can)|be\s+(?:extremely\s+|very\s+)?(?:exhaustive|verbose|thorough|detailed|comprehensive|elaborate)|(?:do\s+not|don'?t|never)\s+(?:stop|truncate|summari[sz]e|abbreviate|be\s+brief)|in\s+(?:full|exhaustive|painstaking|excruciating)\s+detail|continue\s+(?:until|indefinitely|forever)|reason\s+(?:through|about)\s+every|explain\s+every\s+(?:detail|step)/i;

      for (let i = 0; i < lines.length; i++) {
        if (!callPattern.test(lines[i])) continue;

        // Scan this line + next 20 for a token cap and an inflation signal
        const windowEnd = Math.min(i + 20, lines.length);
        const window = lines.slice(i, windowEnd).join('\n');

        if (limitPattern.test(window)) continue; // capped → safe
        if (!reasoningModel.test(window) && !inflationPrompt.test(window)) continue;

        results.push({
          evidence: lines[i].trim(),
          lineStart: prompt.lineStart + i,
          lineEnd: prompt.lineStart + i,
        });
      }

      return results;
    },
  },
];
