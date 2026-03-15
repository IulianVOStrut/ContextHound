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

export const encodingRules: Rule[] = [
  {
    id: 'ENC-001',
    title: 'Base64 encoding of user-controlled variable near prompt construction',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    mitre: 'T1027',
    remediation:
      'Never use Base64 encoding to sanitise user input before inserting it into a prompt. LLMs can decode Base64 and may execute embedded instructions. Validate and delimit input as plaintext instead.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Skip plain-text files — Base64 API calls do not appear in raw prompts
      if (prompt.kind === 'raw') return [];

      // For full-file code-block extractions, require prompt-construction context
      // so we do not flag Base64 used in unrelated parts of the codebase.
      if (prompt.kind === 'code-block') {
        const hasPromptContext =
          /(?:messages\s*(?:\??\.)?\s*push|role\s*:\s*['"`](?:system|user)|systemPrompt\s*[=+]|\.prompt\s*[=+]|prompt\s*\+=)/i.test(
            prompt.text,
          );
        if (!hasPromptContext) return [];
      }

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // atob(variable) or btoa(variable) — argument is a variable, not a literal
      const base64VarPattern = /(?:atob|btoa)\s*\(\s*(?!['"`\d])\s*[a-zA-Z_$]/i;
      // Buffer.from(variable, 'base64') — decoding from base64 using a variable
      const bufferDecodePattern =
        /Buffer\.from\s*\(\s*(?!['"`\d])\s*[a-zA-Z_$][^,)]*,\s*['"]base64['"]/i;

      lines.forEach((line, i) => {
        if (base64VarPattern.test(line) || bufferDecodePattern.test(line)) {
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
    id: 'ENC-002',
    title: 'Hidden Unicode control characters detected in prompt asset',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1027',
    remediation:
      'Remove all invisible Unicode control characters (zero-width spaces, bidi overrides) from prompt source files. Add a Unicode normalization step to your ingestion pipeline and reject content containing unexpected control characters.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Zero-width spaces, joiners, bidi overrides, and invisible formatting characters
      const hiddenUnicodePattern =
        /[\u200B-\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069\uFEFF]/;
      // Only flag when near instruction-like keywords to reduce false positives
      const instructionContextPattern =
        /(?:ignore|system|developer|tool|execute|override|instruction|forget|bypass|always|never)\b/i;

      lines.forEach((line, i) => {
        if (hiddenUnicodePattern.test(line) && instructionContextPattern.test(line)) {
          results.push({
            evidence: `[hidden Unicode] ${line.trim().replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '\u26AF')}`,
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });

      return results;
    },
  },
  {
    id: 'ENC-003',
    title: 'Unicode Tags block characters detected — steganographic injection risk',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1027',
    remediation:
      'Strip or reject all characters in the Unicode Tags block (U+E0000–U+E007F) from any externally sourced content before it enters a prompt. These invisible characters are used in active exploits to hide instructions from human reviewers while remaining readable to LLMs.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Tags block characters are in the supplementary plane; represented as
      // surrogate pairs \uDB40\uDC00–\uDB40\uDC7F in JS strings.
      const tagsPattern = /\uDB40[\uDC00-\uDC7F]/;
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      lines.forEach((line, i) => {
        if (tagsPattern.test(line)) {
          results.push({
            evidence: `[Unicode Tags block chars] ${line.trim().slice(0, 100)}`,
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },
  {
    id: 'ENC-004',
    title: 'Consecutive zero-width character sequence — covert encoding detected',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1027',
    remediation:
      'Remove all zero-width characters (ZWJ U+200D, ZWNJ U+200C, ZWSP U+200B) from externally sourced content. Sequences of 3 or more consecutive zero-width characters are a strong indicator of binary steganography used to smuggle hidden instructions across multi-modal inputs.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // 3+ consecutive ZWJ/ZWNJ/ZWSP = steganographic bit-encoding scheme
      const zwjSequencePattern = /[\u200B\u200C\u200D]{3,}/;
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      lines.forEach((line, i) => {
        if (zwjSequencePattern.test(line)) {
          results.push({
            evidence: `[ZWC sequence] ${line.trim().replace(/[\u200B\u200C\u200D]/g, '\u2022').slice(0, 100)}`,
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },
  {
    id: 'ENC-005',
    title: 'Unicode variation selector sequence — invisible payload encoding',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1027',
    remediation:
      'Strip Unicode variation selectors (U+FE00–U+FE0F and U+E0100–U+E01EF) from all externally sourced content. Sequences of variation selectors are used to encode arbitrary binary payloads invisibly alongside normal text.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // VS1–VS16 (BMP): U+FE00–U+FE0F — sequence of 3+ is suspicious
      const vs1to16Pattern = /[\uFE00-\uFE0F]{3,}/;
      // VS17–VS256 (supplementary): surrogate pair \uDB40\uDD00–\uDB40\uDDEF
      const vs17plusPattern = /(?:\uDB40[\uDD00-\uDDEF]){3,}/;
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      lines.forEach((line, i) => {
        if (vs1to16Pattern.test(line) || vs17plusPattern.test(line)) {
          results.push({
            evidence: `[Variation selector sequence] ${line.trim().slice(0, 100)}`,
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },
  {
    id: 'ENC-006',
    title: 'ROT13 or Caesar cipher applied near LLM context',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    mitre: 'T1027',
    remediation:
      'ROT13 and Caesar ciphers are trivially reversible and provide no security. LLMs can decode them and execute obfuscated instructions. Remove cipher encoding from prompt pipelines and validate content in plaintext before insertion.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind === 'raw') return [];
      // rot13() calls, Python codecs rot_13, or charCode ±13 arithmetic
      const pattern =
        /rot[\s_-]?13\s*\(|codecs\.encode\s*\([^)]*['"]rot.13['"]|charCodeAt\s*\([^)]*\)\s*[+\-]\s*13\b/i;
      return matchPattern(prompt, pattern);
    },
  },
];
