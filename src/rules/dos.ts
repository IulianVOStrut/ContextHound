import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const dosRules: Rule[] = [
  {
    id: 'DOS-001',
    title: 'LLM completion call with no token limit — unbounded consumption risk',
    severity: 'medium',
    confidence: 'medium',
    category: 'dos',
    remediation:
      'Always set max_tokens (OpenAI/Anthropic) or max_new_tokens (HuggingFace) on every LLM completion call. Without a limit, an attacker can use ThinkTrap or reasoning-inflation prompts to force the model to generate arbitrarily long outputs, exhausting your token budget and causing runaway costs.',
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

      for (let i = 0; i < lines.length; i++) {
        if (!callPattern.test(lines[i])) continue;

        // Scan this line + next 20 for a closing delimiter and max_tokens
        const windowEnd = Math.min(i + 20, lines.length);
        const window = lines.slice(i, windowEnd).join('\n');

        if (!limitPattern.test(window)) {
          results.push({
            evidence: lines[i].trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      }

      return results;
    },
  },
];
