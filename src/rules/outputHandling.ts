import path from 'path';
import type { Rule, RuleMatch } from './types.js';
import { LLM_CONTEXT } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

// ── Code-execution sinks fed with model output (OUT-003, OUT-004) ────────────
//
// A sink is a bare eval/exec call (not a method such as regex.exec() or
// model.eval(), and not a definition such as `def eval(`), new Function(), a
// child_process exec call, or a database query method. Only the call's
// argument is checked for model-output names, not the whole line.

const LLM_OUTPUT_ARG =
  /\b(?:llm\w*|ai(?:Response|Output|Result|Text|Reply|Answer|_response|_output|_result)\w*|gpt\w*|claude\w*|completion\w*|response|output|answer|generated\w*|reply)\b|message\.content|choices\s*\[/i;
const SINK_DEFINITION = /\b(?:def|function)\s+(?:eval|exec)\s*\(|\b(?:eval|exec)\s*\([^)]*\)\s*\{/;

function sinkArgumentLines(prompt: ExtractedPrompt, sink: RegExp): RuleMatch[] {
  const results: RuleMatch[] = [];
  const lines = prompt.text.split('\n');
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) return;
    if (SINK_DEFINITION.test(line)) return;
    const m = sink.exec(line);
    if (!m) return;
    const argument = line.slice(m.index + m[0].length);
    if (LLM_OUTPUT_ARG.test(argument)) {
      results.push({ evidence: trimmed, lineStart: prompt.lineStart + i, lineEnd: prompt.lineStart + i });
    }
  });
  return results;
}

export const outputHandlingRules: Rule[] = [
  {
    id: 'OUT-001',
    title: 'LLM JSON output parsed without schema validation',
    severity: 'critical',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Always validate JSON parsed from LLM output using a schema library (Zod, AJV, Joi, Yup) before accessing properties or driving application logic. Never trust the model to conform to the requested schema.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Only analyse code-block extractions (full file context needed to check
      // for the presence or absence of a schema validator in the same file).
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;
      // Model output only exists in files that call a model.
      if (!LLM_CONTEXT.test(text)) return [];

      // JSON.parse / json.loads called on a variable whose name suggests LLM output
      const llmOutputNames =
        /(?:content|message|output|completion|response|result|text|body|answer|reply)\b/i;
      const jsonParsePattern =
        /JSON\.parse\s*\(\s*(?!['"`{\[]|\d)\s*[a-zA-Z_$][a-zA-Z0-9_$.[\]'"]*\s*[)]/i;
      // Python json.loads with a variable argument
      const pyJsonLoadPattern =
        /json\.loads\s*\(\s*(?!['"`{\[]|\d)\s*[a-z_][a-z0-9_$.[\]'"]*\s*[)]/i;

      // Presence of a schema validation library in the file.
      // (?<!JSON)\.parse avoids matching JSON.parse: we want Zod/AJV .parse() only.
      const schemaValidatorPattern =
        /(?:(?<!JSON)\.parse\s*\(|\.safeParse\s*\(|\.validate\s*\(|ajv\b|new\s+Ajv|Joi\s*\.|z\s*\.\s*(?:object|string|number|array|boolean|enum|union|infer)\b|yup\s*\.)/i;
      // Python schema validators
      const pyValidatorPattern =
        /(?:pydantic|marshmallow|cerberus|voluptuous|jsonschema\.validate|TypeAdapter)/i;

      const hasValidator = schemaValidatorPattern.test(text) || pyValidatorPattern.test(text);
      if (hasValidator) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      lines.forEach((line, i) => {
        const isJsonParse = jsonParsePattern.test(line) || pyJsonLoadPattern.test(line);
        if (!isJsonParse) return;
        // Confirm the argument looks like LLM output (by variable name)
        if (!llmOutputNames.test(line)) return;
        results.push({
          evidence: line.trim(),
          lineStart: prompt.lineStart + i,
          lineEnd: prompt.lineStart + i,
        });
      });

      return results;
    },
  },
  {
    id: 'OUT-002',
    title: 'LLM output rendered via Markdown or HTML without sanitization',
    severity: 'critical',
    confidence: 'medium',
    category: 'exfiltration',
    remediation:
      'Pipe all LLM-generated Markdown or HTML through DOMPurify (or equivalent) before rendering. Configure it to strip remote image sources and script tags to prevent data exfiltration via injected tracking pixels.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Markdown/HTML rendering calls
      const mdRenderPattern =
        /(?:marked\s*[.(]|marked\.parse\s*\(|markdownIt\s*[.(]|new\s+MarkdownIt|showdown|micromark\s*\(|dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:)/i;

      if (!mdRenderPattern.test(text)) return [];

      // Presence of a sanitizer in the same file
      const sanitizerPattern = /(?:DOMPurify|dompurify|sanitize\s*\(|createDOMPurify)/i;
      if (sanitizerPattern.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      lines.forEach((line, i) => {
        if (!mdRenderPattern.test(line)) return;
        // Only flag when the argument is a variable (not a string literal)
        const afterCall = line.replace(mdRenderPattern, '');
        if (/^\s*['"`]/.test(afterCall)) return;
        results.push({
          evidence: line.trim(),
          lineStart: prompt.lineStart + i,
          lineEnd: prompt.lineStart + i,
        });
      });

      return results;
    },
  },
  {
    id: 'OUT-003',
    title: 'LLM output used directly in exec(), eval(), or database query',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never execute LLM output as code or SQL. Parse the response into a strict schema first, then use parameterised queries or a dedicated command parser. Treat all model output as untrusted user input.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      return sinkArgumentLines(
        prompt,
        /(?<![.\w$])(?:eval|exec|execSync|execFile)\s*\(|\bnew\s+Function\s*\(|\b(?:child_process|cp)\s*\.\s*(?:exec|execSync|execFile)\s*\(|\b(?:db|connection|pool|client|knex|sequelize)\s*(?:\??\.)\s*(?:query|execute|run|raw)\s*\(/i,
      );
    },
  },
  {
    id: 'OUT-005',
    title: 'LLM output written to shared cache without validation: cache poisoning risk',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    mitre: 'T1565',
    remediation:
      'Never store raw LLM completions directly in a shared cache (Redis, Memcached, node-cache). Validate and sanitise the output before caching, sign or hash cached values to detect tampering, and re-validate on retrieval before use in any downstream prompt. A cache poisoning attack lets one adversarial request inject malicious content into responses served to all future callers who hit the same cache key.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Must have both an LLM completion call and a cache write in the same file
      const llmCallPattern =
        /(?:\.chat\.completions\.create|\.messages\.create|\.complete\s*\(|ChatOpenAI\b|ChatAnthropic\b|\.invoke\s*\()/i;
      const cacheWritePattern =
        /(?:(?:redis|cache|memcached|nodeCache|cacheClient|store)\s*(?:\??\.)?\s*(?:set|put|store|hset|setex|mset)\s*\(|await\s+cache\.set\s*\(|\.setCache\s*\()/i;

      if (!llmCallPattern.test(text) || !cacheWritePattern.test(text)) return [];

      // Suppress if a validation or signing step is present between the LLM call and cache write
      if (/(?:validateCache|sanitiseCache|sanitizeCache|hashResponse|signedCache|cacheHash|hmac|sign(?:ature)?)\s*\(/i.test(text)) return [];

      // Flag the cache write line when its argument contains an LLM output variable name
      const llmOutputArgPattern =
        /\b(?:response|completion|output|result|answer|content|message|generated|choices)\b/i;

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      lines.forEach((line, i) => {
        if (cacheWritePattern.test(line) && llmOutputArgPattern.test(line)) {
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
    id: 'OUT-004',
    title: 'Python eval() or exec() called with LLM-generated output',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never pass LLM-generated output to eval() or exec() in Python. Parse the response into a validated schema (e.g. Pydantic) first, then execute only predefined, constrained operations. Treat all model output as untrusted user input.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const ext = path.extname(filePath).toLowerCase();
      if (ext !== '.py') return [];

      return sinkArgumentLines(prompt, /(?<![.\w$])(?:eval|exec)\s*\(/);
    },
  },
];
