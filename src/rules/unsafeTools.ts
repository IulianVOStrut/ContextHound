import type { Rule, RuleMatch } from './types.js';
import { firstMatchingLine } from './types.js';
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

export const unsafeToolsRules: Rule[] = [
  {
    id: 'TOOL-001',
    title: 'Unbounded tool execution (run any command / browse anywhere)',
    severity: 'critical',
    confidence: 'high',
    category: 'unsafe-tools',
    remediation: 'Restrict tool use with an explicit allowlist. State: "You may only use the following tools: [list]. Do not use any others."',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Broad unbounded execution language, plus backtick/shell substitution
      // patterns that could survive into agentic shell calls (Gemini CLI Issue 2 class).
      const pattern = /(?:run (any|all|arbitrary) (command|code|script)|execute (any|arbitrary) (command|code|program)|browse (anywhere|any (site|url|website))|access (any|all) (file|system|resource|endpoint)|do anything the user (asks?|requests?|wants?)|`[^`]{1,80}`\s*(?:to run|to execute|in the shell|as a command))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'TOOL-002',
    title: 'No tool allowlist or usage policy defined',
    severity: 'medium',
    confidence: 'low',
    category: 'unsafe-tools',
    remediation: 'Add a clear tool policy: "You may only call [tool names]. Refuse any request that requires tools outside this list."',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Prompt-text rule: in source code these phrases are identifiers and comments.
      if (prompt.kind === 'code-block') return [];
      const toolsPattern = /(?:you (can|may|should|are able to) (call|use|invoke|execute)|available tools?|use the (following )?tools?|function calls?)/i;
      const hasPolicy = /(?:only (use|call|invoke)|allowlist|allowed tools?|permitted tools?|do not (use|call) (other|additional|any other)|restrict(ed)? to)/i.test(prompt.text);
      if (hasPolicy) return [];
      const match = firstMatchingLine(prompt, toolsPattern);
      return match ? [match] : [];
    },
  },
  {
    id: 'TOOL-003',
    title: 'Code execution without sandboxing mention',
    severity: 'high',
    confidence: 'medium',
    category: 'unsafe-tools',
    remediation: 'If code execution is needed, explicitly state sandbox constraints and disallow filesystem/network access unless required.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Prompt-text rule: in source code "eval" and "run command" are just code.
      if (prompt.kind === 'code-block') return [];
      // `eval(` followed by a call is code caught in an extraction window, not prose.
      const codeExecPattern = /(?:execute (code|script|program)|run (code|scripts?|programs?|commands?)|\beval\b(?!\s*\()|shell (command|exec))/i;
      const hasSandbox = /(?:sandbox|isolated?|no (file|network|internet|filesystem) access|read.only|cannot access (file|network|disk|system))/i.test(prompt.text);
      if (hasSandbox) return [];
      const match = firstMatchingLine(prompt, codeExecPattern);
      return match ? [match] : [];
    },
  },
  {
    id: 'TOOL-004',
    title: 'Tool description or schema field sourced from user-controlled variable',
    severity: 'critical',
    confidence: 'medium',
    category: 'unsafe-tools',
    remediation:
      'Tool descriptions must be static, server-side strings defined in code. Never populate description, instructions, or system fields in a tool schema from user input or request parameters.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Require a tool-like object structure: an object that has name: "string" (static)
      // This filters out generic objects that happen to have a description field.
      const hasNameStringProp = /name\s*:\s*['"`][^'"`\s]+['"`]/i.test(prompt.text);
      if (!hasNameStringProp) return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // description or instructions key where value starts with a variable (not a string literal)
      const descVarPattern =
        /(?:description|instructions?)\s*:\s*(?!['"`\d])\s*[a-zA-Z_$][a-zA-Z0-9_$.[\]'"]*\s*[,}]/i;

      lines.forEach((line, i) => {
        if (descVarPattern.test(line)) {
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
    id: 'TOOL-005',
    title: 'Tool name or endpoint URL sourced from user-controlled input',
    severity: 'critical',
    confidence: 'high',
    category: 'unsafe-tools',
    remediation:
      'Tool names and endpoint URLs must be static allowlists defined in server-side code. Never populate them from req.body, req.query, or any other user-controlled source.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // name or url field set from an HTTP source via template literal or property access
      const dynamicToolPattern =
        /(?:name|url|endpoint)\s*:\s*(?:\$\{(?:req|request|ctx|input|user|params|query)\b|(?:req|request|ctx)\s*(?:\??\.)?\s*(?:body|query|params))/i;

      lines.forEach((line, i) => {
        if (dynamicToolPattern.test(line)) {
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
