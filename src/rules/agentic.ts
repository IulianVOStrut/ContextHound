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
    mitre: 'T1078',
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
    mitre: 'T1546',
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
  {
    id: 'AGT-008',
    title: 'Agent assumes IAM role or grants permissions based on LLM output (ASI03)',
    severity: 'critical',
    confidence: 'medium',
    category: 'agentic',
    mitre: 'T1548',
    remediation:
      'Never call IAM, RBAC, or credential-assignment functions with values derived from LLM output. A prompt injection or jailbreak can escalate the agent\'s own privileges by inducing it to call assumeRole, grantAccess, or setPermissions with an attacker-chosen role ARN or permission set. Resolve permitted roles from a static allowlist in your application code, never from model responses.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      const iamPattern =
        /(?:assumeRole|putRolePolicy|attachRolePolicy|createRole|grantAccess|setPermissions?|addPermissions?|elevatePrivilege|setCredentials?|assignRole)\s*[.(]/i;
      const llmOutputPattern =
        /\b(?:response|output|result|completion|llm_?output|model_?output|answer|generated|content|choices)\b/i;

      lines.forEach((line, i) => {
        if (iamPattern.test(line) && llmOutputPattern.test(line)) {
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
  {
    id: 'AGT-009',
    title: 'Agent loads tool or plugin from variable path or external URL at runtime (ASI04)',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    mitre: 'T1059',
    remediation:
      'Never load tools, plugins, or modules at runtime from user-controlled values, LLM-generated paths, or dynamic imports without an explicit allowlist. An attacker who can influence the loaded path or URL can substitute a malicious binary or script for a legitimate tool. Resolve tool implementations from a trusted, static registry at startup.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      // Detect: agent.loadTool/addTool/loadPlugin(variable) or dynamic import(variableNamedWithTool/Plugin/Url)
      const pattern =
        /(?:agent|executor|planner|runner)\s*\.(?:loadTool|addTool|registerTool|loadPlugin|importTool)\s*\(\s*(?!['"`])[a-z_$]|(?:await\s+)?import\s*\(\s*[a-z_$][a-z0-9_$.]*(?:Url|Path|Plugin|Tool|Module)\b/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-010',
    title: 'Raw agent output forwarded to another agent without trust boundary validation (ASI07)',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    mitre: 'T1190',
    remediation:
      'Never pass one agent\'s raw output directly as the instruction payload to another agent or message bus without signing or schema validation. In multi-agent pipelines, a compromised upstream agent can inject instructions into every downstream agent that receives its output. Validate, sanitise, and schema-check inter-agent messages at each hop.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;

      // Suppress if message signing / cryptographic verification is present
      const signingGuard = /hmac|sign(?:ature)?|jwt|verify|bearer\s+token|shared.?secret/i;
      if (signingGuard.test(text)) return [];

      // Detect: agent/broker send/forward/route/dispatch called with another agent's output
      const pattern =
        /(?:agent|broker|orchestrator|router|hub|bus)\w*\s*\.(?:send|forward|route|dispatch|relay|publish|invoke|call|run)\s*\(\s*(?:await\s+)?\w+\.(?:output|result|message|response|content|lastMessage|text)\b/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'AGT-011',
    title: 'Agent step error silently swallowed — downstream steps proceed on bad state (ASI08)',
    severity: 'high',
    confidence: 'medium',
    category: 'agentic',
    remediation:
      'Never swallow exceptions from agent plan steps without halting or flagging the run. Silently catching errors allows subsequent steps to execute against incomplete or corrupted state, which can compound failures or be exploited to skip safety checks. Re-throw, reject the promise, or set an explicit error/aborted state that downstream steps check before proceeding.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;

      // Only fire in agent step/plan execution context
      if (!/agent\.(?:run|execute|invoke|step)\s*\(|executeStep\b|runPlan\b|AgentExecutor\b|planStep\b|chain\.(?:run|invoke|call)\s*\(/i.test(text)) return [];

      // Must have a try/catch to be relevant
      if (!/try\s*\{/.test(text)) return [];

      // Suppress if errors are properly propagated or the run is aborted
      if (/\bthrow\b|\breject\s*\(|\berrorState\b|\berror\s*=\s*(?!null|false)|failed\s*=\s*true|status\s*=\s*['"`](?:error|fail|abort)/i.test(text)) return [];

      // Flag the catch line as evidence
      const pattern = /\bcatch\s*\([^)]*\)\s*\{/i;
      return matchPattern(prompt, pattern);
    },
  },
];
