import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

function matchPattern(prompt: ExtractedPrompt, pattern: RegExp): RuleMatch[] {
  const results: RuleMatch[] = [];
  const lines = prompt.text.split('\n');
  lines.forEach((line, i) => {
    if (pattern.test(line)) {
      results.push({
        evidence: line.trim(),
        lineStart: prompt.lineStart + i,
        lineEnd: prompt.lineStart + i,
      });
    }
  });
  return results;
}

export const agenticRules: Rule[] = [
  {
    id: 'AGT-001',
    title: 'Tool call parameter receives system-prompt content',
    severity: 'critical',
    confidence: 'high',
    category: 'agentic',
    remediation:
      'Never pass raw system-prompt or instructions fields as tool call arguments. Sanitise and bound the data before it reaches any tool parameter, and validate tool inputs against a strict schema.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Detect tool_call/function_call argument values that reference system: or instructions: content
      const pattern =
        /(?:tool_call|function_call)\s*[({].*?(?:["'](?:system|instructions?)["']\s*:\s*|arguments?\s*:\s*["'][^"']*(?:system|instructions?))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-002',
    title: 'Agent loop with no iteration or timeout guard',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Add a finite bound on agent loops: set max_iterations, max_steps, max_turns, timeout, or recursion_limit in your agent config or system prompt to prevent unbounded execution.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      // Applies to code-block kind in files containing an agent loop pattern
      if (prompt.kind !== 'code-block') return [];

      const guardPattern =
        /(?:max_iterations|max_steps|max_turns|timeout|recursion_limit)\s*[=:]/i;
      const loopPattern =
        /(?:while\s*(?:True|true|\(true\))|agent\.run\s*\(|AgentExecutor|\.invoke\s*\(|run_until_done|agent_loop)/i;

      if (!loopPattern.test(prompt.text)) return [];
      if (guardPattern.test(prompt.text)) return [];

      // Return a match at the first loop keyword location
      const lines = prompt.text.split('\n');
      const results: RuleMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (loopPattern.test(lines[i])) {
          results.push({
            evidence: lines[i].trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          break; // one finding per file is enough
        }
      }
      void filePath;
      return results;
    },
  },
  {
    id: 'AGT-003',
    title: 'Agent memory written from unvalidated LLM output',
    severity: 'high',
    confidence: 'high',
    category: 'agentic',
    remediation:
      'Validate and sanitise LLM output before writing to agent memory or vector stores. Never pass raw model responses directly to memory.save(), memory.add(), or vectorstore.upsert() without schema validation.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      // Memory write calls with an argument that looks like an LLM output variable
      const pattern =
        /(?:memory\.(?:save|add|append)|vectorstore\.upsert|vector_store\.upsert|memory_store\.(?:set|add|write))\s*\(\s*(?:response|output|result|completion|llm_output|model_output|answer|generated)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-004',
    title: 'Plan injection — user input interpolated into agent planning prompt',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Wrap user input in a trust-boundary delimiter before including it in agent planning prompts. Use a structured object field (not string concatenation) and label user content as untrusted data, not instructions.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // User input interpolated into planning/task/goal/objective strings
      const pattern =
        /(?:plan|task|goal|objective|agent_instructions?)\s*[=+:]\s*[`"']?[^`"'\n]*\$\{?\s*(?:user(?:Input|Query|Message|Request)|request|query|input)\s*\}?/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-005',
    title: 'Agent trusts claimed identity without cryptographic verification',
    severity: 'critical',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Never grant elevated trust based solely on a message field claiming to be from a specific agent (agentId, sender, source, from_agent). Any agent can forge these fields. Verify inter-agent messages with HMAC signatures, JWT tokens, or a shared secret before acting on claimed identity.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;

      // Only fire when there is no cryptographic verification present
      const verifyPattern = /hmac|signature|verify|jwt|bearer\s+token|shared.?secret/i;
      if (verifyPattern.test(text)) return [];

      // Detect: conditional trust decision based on a claimed agent identity field
      const pattern =
        /(?:agentId|agent_id|from_agent|sender|source)\s*[!=]={1,2}\s*['"`][^'"`]+['"`]/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-006',
    title: 'Raw agent output chained as input to another agent without validation',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Never pass one agent\'s raw output directly as the instruction input to another agent. Validate, sanitize, and schema-check intermediate outputs before they become instructions. A compromised or manipulated first agent can inject malicious instructions into the entire downstream chain.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      // Detect: agent/chain call where argument is another agent's .output/.content/.result/.text
      const pattern =
        /\.(?:run|invoke|generate|call|complete|chat)\s*\(\s*(?:await\s+)?(?:\w+\.(?:output|content|text|result|choices|message|\[\s*0\s*\])|output|result)\b/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-007',
    title: 'Agent modifies its own system prompt, instructions, or tool list at runtime',
    severity: 'critical',
    confidence: 'high',
    category: 'agentic',
    remediation:
      'An agent should never overwrite its own system prompt, instructions, or tools with LLM-generated content. This is a self-modification attack vector — a malicious prompt can permanently alter agent behaviour for all subsequent interactions. Keep agent configuration immutable at runtime.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Self-modification: agent/self.config field assigned from LLM output variable
      const configWritePattern =
        /(?:agent|self)\s*\.(?:system_prompt|systemPrompt|instructions?|system|tools?)(?:\s*\+?=\s+|\.(?:append|extend|add|push)\s*\()/i;
      const llmOutputPattern =
        /\b(?:response|output|result|completion|llm_output|model_output|answer|generated|content|choices)\b/i;

      lines.forEach((line, i) => {
        if (configWritePattern.test(line) && llmOutputPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });

      return results;
    },
  },
];
