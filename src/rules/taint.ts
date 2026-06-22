import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

// ── Lightweight intra-file taint tracking (JS/TS) ─────────────────────────────
//
// Complements the name-based INJ rules by following *arbitrarily named*
// variables from a clearly-untrusted source into a prompt sink. It is
// deliberately conservative — only unambiguous external sources are treated as
// tainted, sanitiser wrappers clear taint, and findings the name-based INJ-001
// rule already covers are skipped to avoid double-reporting.

// Unambiguous untrusted external input: HTTP request fields, CLI args, and
// browser URL / cookie sources.
const TAINT_SOURCE =
  /\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|form|args|values)\b|\bprocess\.argv\b|\b(?:window\s*\.\s*)?location\s*\.\s*(?:search|hash|href)\b|\bdocument\s*\.\s*cookie\b|\.searchParams\s*\.\s*get\s*\(/;

// Presence of a sanitiser / validator / coercion on the RHS clears taint.
const SANITIZER =
  /\b(?:sanitiz|escape|validate|allowlist|allow_list|encodeURI|encodeURIComponent|parseInt|parseFloat|Number\s*\(|\.safeParse\s*\(|z\s*\.\s*\w+|zod|DOMPurify|striptags|escapeHtml)/i;

// Variable roots already handled by INJ-001's user-input heuristic — skip these
// so taint stays purely additive.
const USER_VARS_RE =
  /^(?:user[a-z_]*|input|query|message|request|text|prompt|content)$/i;

// A template literal is treated as a prompt sink when its text reads like one.
const PROMPT_LIKE =
  /\b(?:you are|your (?:role|task|job)|system|assistant|prompt|answer|summari[sz]|translat|respond|reply|instruction|context)\b/i;

const DECL_DESTRUCTURE = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$/;
const DECL_SIMPLE = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$/;
const REASSIGN = /^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$/;

function declaredNames(line: string): { names: string[]; rhs: string } | null {
  let m = DECL_DESTRUCTURE.exec(line);
  if (m) {
    const names = m[1].split(',').map(part => {
      const p = part.trim();
      // `{ a: b }` binds `b`; `{ a }` binds `a`; `{ a = d }` binds `a`.
      const alias = p.includes(':') ? p.split(':')[1] : p;
      return alias.replace(/=.*$/, '').trim().replace(/[.\s]/g, '');
    }).filter(Boolean);
    return { names, rhs: m[2] };
  }
  m = DECL_SIMPLE.exec(line) ?? REASSIGN.exec(line);
  if (m) return { names: [m[1]], rhs: m[2] };
  return null;
}

function referencesTainted(rhs: string, tainted: Set<string>): boolean {
  for (const t of tainted) {
    if (new RegExp(`\\b${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(rhs)) return true;
  }
  return false;
}

function collectTainted(lines: string[]): Set<string> {
  const tainted = new Set<string>();
  // A few fixed-point passes capture simple one-hop aliasing in any order.
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (const line of lines) {
      const decl = declaredNames(line);
      if (!decl) continue;
      const { names, rhs } = decl;
      if (SANITIZER.test(rhs)) continue; // sanitised → clean
      if (TAINT_SOURCE.test(rhs) || referencesTainted(rhs, tainted)) {
        for (const n of names) {
          if (n && !tainted.has(n)) { tainted.add(n); changed = true; }
        }
      }
    }
    if (!changed) break;
  }
  return tainted;
}

function lineNumberAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

export const taintRules: Rule[] = [
  {
    id: 'INJ-015',
    title: 'Untrusted external input flows into a prompt (taint analysis)',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1190',
    remediation:
      'A value derived from an untrusted source (HTTP request, CLI argument, or browser URL/cookie) reaches a prompt without sanitisation. Validate or allowlist the value, wrap it in clear untrusted-content delimiters, and label it as untrusted before interpolating it into the prompt.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const content = prompt.text;
      if (!TAINT_SOURCE.test(content)) return [];

      const tainted = collectTainted(content.split('\n'));
      if (tainted.size === 0) return [];

      const results: RuleMatch[] = [];
      const seenLines = new Set<number>();

      // Walk every backtick template literal; flag prompt-like ones that
      // interpolate a tainted root variable.
      const templateRe = /`(?:[^`\\]|\\.)*`/gs;
      let tm: RegExpExecArray | null;
      while ((tm = templateRe.exec(content)) !== null) {
        const tpl = tm[0];
        if (!PROMPT_LIKE.test(tpl)) continue;
        const interpRe = /\$\{([^}]+)\}/g;
        let im: RegExpExecArray | null;
        while ((im = interpRe.exec(tpl)) !== null) {
          const root = im[1].trim().split(/[.[(?\s]/)[0];
          if (!root || !tainted.has(root) || USER_VARS_RE.test(root)) continue;
          const absIdx = tm.index + im.index;
          const lineNo = prompt.lineStart - 1 + lineNumberAt(content, absIdx);
          if (seenLines.has(lineNo)) continue;
          seenLines.add(lineNo);
          results.push({
            evidence: `\${${im[1].trim()}} (tainted: ${root})`,
            lineStart: lineNo,
            lineEnd: lineNo,
          });
        }
      }
      return results;
    },
  },
];
