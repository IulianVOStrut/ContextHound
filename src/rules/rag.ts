import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

// Shared retrieval call pattern used by RAG-005 and RAG-006
const RETRIEVAL_CALL_PATTERN =
  /(?:similaritySearch|similarity_search|vectorStore\.query|vector_store\.query|vectorstore\.query|retriever\.(?:get_relevant_documents|invoke|retrieve)|retrieve(?:Documents?|Chunks?|Context)?\s*\(|\.search\s*\(\s*(?!['"`])|docsearch\.search|pinecone\.query|weaviate\.query|qdrant\.search|milvus\.search|chromadb\.query|faiss\.search)/i;

// RAG-001: does a message's content expression carry retrieved or external data?
// String literals and constant-style names (SYSTEM_PROMPT, systemPrompt) do not.
const RETRIEVED_NAME =
  /(?:context|docs?\b|documents?|chunks?|passages?|retriev|search|results?\b|knowledge|\bkb\b|\brag|snippets?|sources?\b|external|fetched|scraped|crawl|webpage|pageContent|pageText|toolOutput|toolResult|upload|memory)/i;

function isRetrievedContent(expr: string): boolean {
  const e = expr.replace(/\s+/g, ' ');
  if (/^(['"])/.test(e)) return false;                       // plain string literal
  if (e.startsWith('`')) {
    const inner = [...e.matchAll(/\$<([^>]*)>/g)].map(m => m[1]).join(' ');
    return inner.length > 0 && RETRIEVED_NAME.test(inner);
  }
  if (/^[A-Z][A-Z0-9_]*$/.test(e)) return false;              // UPPER_SNAKE constant
  return RETRIEVED_NAME.test(e);
}

export const ragRules: Rule[] = [
  {
    id: 'RAG-001',
    title: 'Retrieved content injected as system-role message',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    remediation:
      'Never assign retrieved or external content to role: "system". Use role: "tool" or role: "user" and label it as untrusted context with clear delimiters.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Detect role: "system" assignments
      const systemRolePattern = /role\s*:\s*['"`]system['"`]/i;

      lines.forEach((line, i) => {
        const roleMatch = systemRolePattern.exec(line);
        if (!roleMatch) return;
        // Look only inside the same message object: from the role to the first
        // closing brace, at most three lines on. The old window ran into the
        // next message and flagged `{ role: 'user', content: input }`.
        const window = [line.slice(roleMatch.index), ...lines.slice(i + 1, i + 4)].join('\n');
        // Template expressions are rewritten to $<...> first so their braces do
        // not end the object early.
        const objectText = window.replace(/\$\{([^}]*)\}/g, '$<$1>').split('}')[0];
        const content = /content\s*:\s*([^,\n]+)/i.exec(objectText)?.[1]?.trim();
        if (!content || !isRetrievedContent(content)) return;
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
    id: 'RAG-002',
    title: 'Instruction-like phrases in document ingestion pipeline',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Filter instruction-like strings from documents at ingestion time, before they are stored or embedded. Use a phrase denylist and strip or reject documents that match.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const text = prompt.text;

      // Require evidence of a document iteration loop
      const ingestionPattern =
        /(?:\.(?:forEach|map|filter|reduce)\s*\(\s*(?:async\s+)?\(?(?:doc|chunk|passage|item|record|text)\b|for\s+(?:const|let|var)\s+\w+\s+of\s+\w*(?:docs?|chunks?|documents?|passages?|texts?|items?)\w*)/i;

      if (!ingestionPattern.test(text)) return [];

      // Look for corpus-poisoning instruction markers inside the loop body
      const poisonPattern =
        /(?:system\s*prompt\s*:|always\s+return|never\s+redact|debug\s+mode\s*[=:]\s*true|confidential\s+instructions?\s*:|override\s+(?:system|instructions?|constraints?)|ignore\s+(?:previous|all)\s+(?:instructions?|rules?|constraints?))/i;

      const lines = text.split('\n');
      lines.forEach((line, i) => {
        if (poisonPattern.test(line)) {
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
    id: 'RAG-003',
    title: 'Agent memory written directly from user-controlled input',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Validate and sanitize all data before writing to memory stores. Store only structured, explicit facts (name, locale); never store free-form instructions or raw message content. Require user confirmation before persisting preferences.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Memory store write calls
      const memoryWritePattern =
        /(?:memory\s*(?:\??\.)?\s*(?:add|set|store|save|push|append)\s*\(|saveMemory\s*\(|storeMemory\s*\(|addMemory\s*\(|conversationStore\s*(?:\??\.)?\s*(?:set|add)\s*\(|memoryStore\s*(?:\??\.)?\s*(?:add|set)\s*\(|\.remember\s*\()/i;
      // User-controlled input sources on the same line
      const userInputPattern =
        /(?:req\.body|req\.query|req\.params|request\.body|ctx\.body|ctx\.request\.body|userInput|userMessage)\b/i;

      lines.forEach((line, i) => {
        if (memoryWritePattern.test(line) && userInputPattern.test(line)) {
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
    id: 'RAG-004',
    title: 'Prompt instructs model to treat retrieved context as highest priority',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Explicitly state that retrieved context is untrusted data and must not override developer instructions. Retrieved content should inform — not direct — model behavior.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:(?:retrieved|context|documents?|knowledge\s+base|search\s+results?).{0,60}(?:highest\s+priority|overrides?|takes?\s+precedence|more\s+important\s+than|supersedes?|always\s+follow|must\s+follow)|(?:always|must|strictly)\s+follow\s+(?:the\s+)?(?:retrieved|context|documents?|knowledge\s+base|search\s+results?))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'RAG-005',
    title: 'Provenance-free retrieval — chunks inserted into prompt without source metadata check',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Attach provenance metadata (source, owner, last_reviewed) to every retrieved chunk and validate it before the chunk enters the prompt. If provenance cannot be established, reject the chunk or quarantine it behind a trust barrier. Provenance tags let you enforce trust-tier filtering downstream.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      // Must have a retrieval call in the file
      if (!RETRIEVAL_CALL_PATTERN.test(prompt.text)) return [];

      // A provenance check accesses source/owner/trust metadata or a score on the result
      const PROVENANCE_CHECK =
        /(?:\.(?:source|metadata\.source|owner|last_reviewed|trust_level|trust_score|provenance|origin)\b|chunk(?:s|es)?\[.{0,20}\]\.(?:source|metadata|owner)|\.filter\s*\([^)]*(?:source|owner|trust|provenance))/i;

      if (PROVENANCE_CHECK.test(prompt.text)) return [];

      // Flag the first retrieval call site
      const lines = prompt.text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (RETRIEVAL_CALL_PATTERN.test(lines[i])) {
          return [{
            evidence: lines[i].trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          }];
        }
      }
      return [];
    },
  },
  {
    id: 'RAG-006',
    title: 'No ACL or trust-tier filter applied before retrieval enters the prompt',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    remediation:
      'Apply ACL and trust-tier filters as part of the retrieval query, not as a post-retrieval step. Pass a filter/where/metadata_filter/namespace parameter to your vector store query to restrict results to documents the caller is authorised to access. Documents that fail the policy must never enter the prompt.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      if (!RETRIEVAL_CALL_PATTERN.test(prompt.text)) return [];

      // A filter is passed when the call includes a filter/where/metadata_filter/score_threshold/namespace/acl parameter
      const FILTER_PARAM =
        /(?:filter\s*:|where\s*:|metadata_filter\s*:|score_threshold\s*:|namespace\s*:|acl\s*:|trust_(?:level|tier)\s*:|filter\s*=\s*\{|\.namespace\s*\(|with_filter\s*\(|with_where\s*\()/i;

      if (FILTER_PARAM.test(prompt.text)) return [];

      const lines = prompt.text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (RETRIEVAL_CALL_PATTERN.test(lines[i])) {
          return [{
            evidence: lines[i].trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          }];
        }
      }
      return [];
    },
  },
  {
    id: 'RAG-007',
    title: 'Document metadata field interpolated into prompt without sanitisation',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    mitre: 'T1190',
    remediation:
      'Treat all document metadata (title, author, description, URL, tags) as untrusted external content. Truncate, strip control characters, or allowlist-validate metadata field values before interpolating them into prompts. Wrap metadata values in delimiters and label them as "untrusted source metadata". An attacker who can write to the document corpus can inject instructions through metadata fields that bypass content-level filters.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Fire on template strings and full code-block extractions, not raw .prompt files
      if (prompt.kind === 'raw') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // ${doc.metadata.X}, ${chunk.metadata.X}, ${document.metadata.X}, ${result.metadata.X}
      const metadataInterpolationPattern =
        /\$\{[^}]{0,200}?\b(?:doc|chunk|document|passage|result|item|record)\b[^}]{0,200}?\.\s*metadata\s*[.[][^}]{0,80}\}/i;

      // Suppress if a sanitiser or truncation is applied near the interpolation
      const sanitiserPattern =
        /(?:truncate|slice|substring|substr|sanitize|sanitise|escape|strip|replace|encode|trim)\s*\(/i;

      lines.forEach((line, i) => {
        if (!metadataInterpolationPattern.test(line)) return;
        const context = lines
          .slice(Math.max(0, i - 3), Math.min(lines.length, i + 4))
          .join('\n');
        if (!sanitiserPattern.test(context)) {
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
