import fs from 'fs';
import path from 'path';
import { getLLMTrigger } from './languages.js';

// ── Encoding normalisation ────────────────────────────────────────────────────
// Applied to prompt text before rule matching so that obfuscated injection
// attempts are caught regardless of encoding layer.

function iterativeUrlDecode(text: string): string {
  let current = text;
  for (let i = 0; i < 5; i++) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }
  return current;
}

function decodeOctalEscapes(text: string): string {
  return text.replace(/\\([0-7]{3})/g, (_, oct: string) =>
    String.fromCharCode(parseInt(oct, 8))
  );
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function tryDecodeBase32(s: string): string | null {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const c of s) {
    const idx = BASE32_CHARS.indexOf(c);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      const code = (value >> bits) & 0xff;
      // Reject non-printable ASCII — avoids replacing legitimate tokens
      if (code < 32 || code > 126) return null;
      output += String.fromCharCode(code);
    }
  }
  return output.length >= 4 ? output : null;
}

function decodeBase32Sequences(text: string): string {
  // Match sequences of 8+ base32 characters (case-insensitive, optional padding).
  // Use lookahead/lookbehind instead of \b so padding '=' chars don't break the boundary.
  return text.replace(/(?<![A-Z2-7=])[A-Z2-7]{8,}={0,6}(?![A-Z2-7=])/gi, (match) => {
    const stripped = match.replace(/=/g, '').toUpperCase();
    const decoded = tryDecodeBase32(stripped);
    return decoded ?? match;
  });
}

// Maps common homoglyph vowels (Latin extended + combining) to ASCII equivalents.
// Catches obfuscation like "1gn0re" → handled by leetspeak; this handles
// scripts that substitute visually similar Unicode vowel letters.
const VOWEL_HOMOGLYPHS: [RegExp, string][] = [
  [/[àáâãäåāăąǎȁȃȧæ]/gi, 'a'],
  [/[èéêëēĕėęěȅȇ]/gi, 'e'],
  [/[ìíîïīĭįǐȉȋ]/gi, 'i'],
  [/[òóôõöøōŏőǒȍȏ]/gi, 'o'],
  [/[ùúûüūŭůűǔȕȗ]/gi, 'u'],
];

function foldVowelHomoglyphs(text: string): string {
  let result = text;
  for (const [pattern, replacement] of VOWEL_HOMOGLYPHS) {
    result = result.replace(pattern, (m) =>
      m === m.toUpperCase() ? replacement.toUpperCase() : replacement
    );
  }
  return result;
}

/**
 * Normalises prompt text through four successive decoding passes so that
 * rules match obfuscated injection content as well as plaintext.
 *
 * Passes (order matters):
 *  1. Iterative URL decode   — catches %xx and double-encoded %25xx
 *  2. Octal escape decode    — catches \151\147\156\157\162\145 → "ignore"
 *  3. Base32 decode          — catches base32-encoded instruction strings
 *  4. Vowel homoglyph fold   — normalises visually substituted vowel characters
 *
 * Not applied to code-block prompts (full source files) to avoid mangling code.
 */
export function normalise(text: string): string {
  let t = text;
  t = iterativeUrlDecode(t);
  t = decodeOctalEscapes(t);
  t = decodeBase32Sequences(t);
  t = foldVowelHomoglyphs(t);
  return t;
}

export interface ExtractedPrompt {
  text: string;
  lineStart: number;
  lineEnd: number;
  kind: 'raw' | 'template-string' | 'object-field' | 'chat-message' | 'code-block';
}

const PROMPT_KEY_PATTERN = /(?:^|["'])(?:system|prompt|instructions?|messages?|role|content|context|directive)(?:["']|\s*:)/i;
const ROLE_CONTENT_PATTERN = /\{\s*["']?role["']?\s*:\s*["'][^"']+["']\s*,\s*["']?content["']?\s*:/i;
const SYSTEM_PHRASE_PATTERN = /(?:you are|your (role|task|job|purpose) is|do not|don't|never|always|must|system:|instructions?:|you must|as an? (ai|assistant|bot))/i;
// Patterns that trigger full-file code-block extraction so multi-line rules can
// analyse the complete context (CMD, RAG, and encoding rules rely on this).
const SHELL_EXEC_PATTERN = /(?:execSync|execFile|spawnSync)\s*\(|(?:exec|spawn)\s*\(\s*[`"']/i;
const MESSAGES_PUSH_PATTERN = /messages\s*(?:\??\.)?\s*push\s*\(\s*\{/i;
const BASE64_CALL_PATTERN =
  /(?:atob|btoa)\s*\(|\.toString\s*\(\s*['"]base64['"]\s*\)|Buffer\.from\s*\([^)]+,\s*['"]base64['"]/i;
const JSON_PARSE_PATTERN = /JSON\.parse\s*\(/i;
const MD_RENDER_PATTERN =
  /(?:marked\s*[.(]|marked\.parse\s*\(|markdownIt\s*[.(]|new\s+MarkdownIt|dangerouslySetInnerHTML\s*=)/i;
// eval(variable) — triggers OUT-003; intentionally excludes eval('string literal')
const EVAL_DYNAMIC_PATTERN = /\beval\s*\(\s*(?!['"`\d{[])/i;
// Vision API image content structure — triggers VIS-001, VIS-002
const VISION_API_PATTERN = /type\s*:\s*['"`]image_url['"`]/i;
// Transcription API calls — triggers VIS-003
const TRANSCRIPTION_API_PATTERN = /\.transcriptions\.create\s*\(|openai\.audio\.transcriptions/i;
// OCR library/API calls — triggers VIS-004
const OCR_API_PATTERN = /Tesseract\.createWorker\s*\(|vision\.textDetection\s*\(/i;
// Browser DOM / URL sources — triggers INJ-011
const DOM_SOURCE_PATTERN = /window\.location\.(?:search|hash|href)|document\.cookie\b|document\.querySelector\s*\(|document\.getElementById\s*\(/i;
// MCP (Model Context Protocol) SDK imports — triggers MCP-001 through MCP-005
const MCP_PATTERN = /@modelcontextprotocol\/sdk|StdioServerTransport|StdioClientTransport|SSEClientTransport|McpServer\b|CreateMessageRequestSchema/i;
// LLM completion calls — triggers DOS-001 in files that don't already match MESSAGES_PUSH_PATTERN
const COMPLETIONS_PATTERN = /\.chat\.completions\.create\s*\(\s*\{|\.messages\.create\s*\(\s*\{/i;

function isCodeFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return [
    '.ts', '.js', '.tsx', '.jsx',
    '.py', '.go', '.rs', '.java', '.kt', '.kts',
    '.cs', '.php', '.rb', '.swift', '.vue',
    '.sh', '.bash', '.c', '.cpp', '.cc', '.h', '.hs',
  ].includes(ext);
}

function isRawPromptFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.prompt', '.txt', '.md'].includes(ext);
}

export function extractPrompts(filePath: string): ExtractedPrompt[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  let results: ExtractedPrompt[];

  if (isRawPromptFile(filePath)) {
    results = extractFromRaw(content);
    // OpenClaw skill files: also emit the full file as code-block so multi-line
    // SKL rules (SKL-004 whole-file frontmatter checks, etc.) fire correctly.
    const base = path.basename(filePath).toLowerCase();
    const norm = filePath.replace(/\\/g, '/').toLowerCase();
    const isSkillMd =
      base === 'skill.md' ||
      norm.includes('/skills/') ||
      norm.includes('.openclaw') ||
      norm.includes('clawhub');
    if (isSkillMd) {
      const lines = content.split('\n');
      results.push({ text: content, lineStart: 1, lineEnd: lines.length, kind: 'code-block' });
    }
  } else if (filePath.endsWith('.json') || filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
    results = extractFromStructured(content);
  } else if (isCodeFile(filePath)) {
    results = extractFromCode(content, filePath);
  } else {
    results = extractFromRaw(content);
  }

  // Apply encoding normalisation to all non-code-block prompts.
  // code-block prompts are full source files — normalising them would mangle
  // code syntax and produce false positives in code-aware rules.
  return results.map(p =>
    p.kind === 'code-block' ? p : { ...p, text: normalise(p.text) }
  );
}

function extractFromRaw(content: string): ExtractedPrompt[] {
  const lines = content.split('\n');
  // Return entire file as one block if it looks like a prompt
  if (SYSTEM_PHRASE_PATTERN.test(content) || content.length > 50) {
    return [{
      text: content,
      lineStart: 1,
      lineEnd: lines.length,
      kind: 'raw',
    }];
  }
  return [];
}

function extractFromStructured(content: string): ExtractedPrompt[] {
  const results: ExtractedPrompt[] = [];
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    if (PROMPT_KEY_PATTERN.test(line)) {
      // Grab up to 20 lines of context
      const start = idx;
      const end = Math.min(idx + 20, lines.length - 1);
      const snippet = lines.slice(start, end + 1).join('\n');
      results.push({
        text: snippet,
        lineStart: start + 1,
        lineEnd: end + 1,
        kind: 'object-field',
      });
    }
  });

  return results;
}

function extractFromCode(content: string, _filePath: string): ExtractedPrompt[] {
  const results: ExtractedPrompt[] = [];
  const lines = content.split('\n');

  // Detect template literals / strings that look like prompts
  let inTemplateLiteral = false;
  let templateStart = 0;
  let templateLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Simple template literal detection (backtick strings)
    const backtickCount = (line.match(/`/g) || []).length;

    if (!inTemplateLiteral && backtickCount % 2 === 1) {
      // Opening backtick
      inTemplateLiteral = true;
      templateStart = i;
      templateLines = [line];
    } else if (inTemplateLiteral && backtickCount % 2 === 1) {
      // Closing backtick
      templateLines.push(line);
      const text = templateLines.join('\n');
      if (SYSTEM_PHRASE_PATTERN.test(text) || PROMPT_KEY_PATTERN.test(text)) {
        results.push({
          text,
          lineStart: templateStart + 1,
          lineEnd: i + 1,
          kind: 'template-string',
        });
      }
      inTemplateLiteral = false;
      templateLines = [];
    } else if (inTemplateLiteral) {
      templateLines.push(line);
      // Safety: bail on very long template literals
      if (templateLines.length > 200) {
        inTemplateLiteral = false;
        templateLines = [];
      }
    }

    // Detect OpenAI-style chat messages {role, content}
    if (ROLE_CONTENT_PATTERN.test(line)) {
      const start = i;
      const end = Math.min(i + 5, lines.length - 1);
      results.push({
        text: lines.slice(start, end + 1).join('\n'),
        lineStart: start + 1,
        lineEnd: end + 1,
        kind: 'chat-message',
      });
    }

    // Detect object keys like system:, prompt:, instructions:
    if (PROMPT_KEY_PATTERN.test(line) && !ROLE_CONTENT_PATTERN.test(line)) {
      const start = i;
      const end = Math.min(i + 15, lines.length - 1);
      results.push({
        text: lines.slice(start, end + 1).join('\n'),
        lineStart: start + 1,
        lineEnd: end + 1,
        kind: 'object-field',
      });
    }
  }

  // Expose the full file as a code-block when it contains patterns that require
  // multi-line analysis: shell exec calls (CMD rules), messages.push (RAG rules),
  // or Base64 API calls (ENC/EXF rules).
  if (
    SHELL_EXEC_PATTERN.test(content) ||
    MESSAGES_PUSH_PATTERN.test(content) ||
    BASE64_CALL_PATTERN.test(content) ||
    JSON_PARSE_PATTERN.test(content) ||
    MD_RENDER_PATTERN.test(content) ||
    EVAL_DYNAMIC_PATTERN.test(content) ||
    VISION_API_PATTERN.test(content) ||
    TRANSCRIPTION_API_PATTERN.test(content) ||
    OCR_API_PATTERN.test(content) ||
    DOM_SOURCE_PATTERN.test(content) ||
    MCP_PATTERN.test(content) ||
    COMPLETIONS_PATTERN.test(content)
  ) {
    results.push({
      text: content,
      lineStart: 1,
      lineEnd: lines.length,
      kind: 'code-block',
    });
  } else {
    // For non-JS/TS languages, check if the file imports an LLM library and
    // emit the whole file as a code-block so that language-agnostic rules fire.
    const langTrigger = getLLMTrigger(path.extname(_filePath).toLowerCase());
    if (langTrigger && langTrigger.test(content)) {
      results.push({
        text: content,
        lineStart: 1,
        lineEnd: lines.length,
        kind: 'code-block',
      });
    }
  }

  return results;
}
