import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const multimodalRules: Rule[] = [
  {
    id: 'VIS-001',
    title: 'User-supplied image URL or base64 passed to vision API without validation',
    severity: 'critical',
    confidence: 'high',
    category: 'multimodal',
    remediation:
      'Validate image URLs against an allowlist of trusted domains before forwarding to a vision model. For base64 data, verify the MIME type and size server-side. Never pass req.body/req.query values directly as image_url.url or source.data: treat them as untrusted input.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Require vision API image-content structure in the file
      const visionApiPattern =
        /(?:type\s*:\s*['"`]image_url['"`]|image_url\s*:\s*\{|inline_data\s*:\s*\{|gpt-4o|gemini.*vision|claude-3)/i;
      if (!visionApiPattern.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      // url: or data: key set to a user-controlled source, including inside a template literal
      // e.g. url: req.body.imageUrl  OR  url: `data:...${req.body.imageData}`
      const userImagePattern =
        /(?:url|data)\s*:\s*(?:`[^`]*\$\{)?(?:req|request|ctx|params|body|query|input|user\w*)[.\[]/i;

      lines.forEach((line, i) => {
        if (userImagePattern.test(line)) {
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
    id: 'VIS-002',
    title: 'User-supplied file path read into vision message (path traversal)',
    severity: 'critical',
    confidence: 'high',
    category: 'multimodal',
    remediation:
      'Never resolve file paths from user input for vision API uploads. Accept only file IDs or pre-signed upload tokens. If a path must be used, resolve it with path.resolve and assert it starts with the expected base directory before calling fs.readFile.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Require vision/multimodal API context so the read is for a vision message
      const visionContextPattern =
        /(?:image_url|inline_data|gpt-4o|gemini.*vision|claude-3.*vision|base64.*image|image.*base64)/i;
      if (!visionContextPattern.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      // fs.readFile/readFileSync with a user-controlled path as the first argument
      const fsReadUserPathPattern =
        /fs\.(?:readFile(?:Sync)?|promises\.readFile)\s*\(\s*(?:req|request|ctx|params|body|query|input|user\w*)[.\[]/i;

      lines.forEach((line, i) => {
        if (fsReadUserPathPattern.test(line)) {
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
    id: 'VIS-003',
    title: 'Audio/video transcription output fed into prompt without sanitization',
    severity: 'high',
    confidence: 'medium',
    category: 'multimodal',
    remediation:
      'Treat transcription output as untrusted external content: the same mitigations as RAG poisoning apply. Wrap it in explicit delimiters labeled "untrusted transcription", reject instruction-like phrases, limit length, and insert it only in role: "user", never role: "system".',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Transcription API or known speech-to-text service detected in the file
      const transcriptionApiPattern =
        /(?:\.transcriptions\.create\s*\(|openai\.audio\.|whisper|assemblyai|deepgram|revai|speechmatics|aws.*transcribe|google.*speech(?:_to_text|2text|Client)|stt_result|asr_result)\b/i;
      if (!transcriptionApiPattern.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      // Transcription result placed directly into message content without sanitization
      const directInjectionPattern =
        /(?:content\s*:\s*(?:transcription|transcript|transcribed|stt|asr|whisper|speechResult)\w*|messages?\s*(?:\??\.)?\s*push\s*\([^)]*(?:transcription|transcript)\w*)/i;

      lines.forEach((line, i) => {
        if (!directInjectionPattern.test(line)) return;

        // Suppress if explicit sanitization is visible in the preceding 3 lines
        const lookback = lines.slice(Math.max(0, i - 3), i + 1).join('\n');
        const hasSanitization =
          /(?:\.replace\s*\(|sanitize|escape|strip|filter|untrusted|delimiter|<transcript>)/i.test(lookback);
        if (!hasSanitization) {
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
    id: 'VIS-004',
    title: 'OCR output interpolated into system instructions',
    severity: 'high',
    confidence: 'medium',
    category: 'multimodal',
    remediation:
      'OCR output is external, attacker-influenced content: a physical document or image can contain injected instructions. Never interpolate it into a system-role message or system prompt. Insert OCR text exclusively in the user turn with clear delimiters, and strip instruction-like phrases before use.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // OCR library or cloud Vision API detected in the file
      const ocrApiPattern =
        /(?:Tesseract\.createWorker|tesseract\.recognize\s*\(|vision\.textDetection\s*\(|vision\.imageAnnotatorClient|textAnnotations\b|documentAi|google\.cloud\.vision)\b/i;
      if (!ocrApiPattern.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      // System-role or system-prompt assignment
      const systemInjectionPattern =
        /(?:role\s*:\s*['"`]system['"`]|systemPrompt\s*[+`=]|system\s*:\s*[`"'])/i;

      // Common variable names for OCR output
      const ocrResultPattern =
        /(?:ocr|textAnnotations?|extractedText|recognizedText|imageText|visionResult|ocrOutput)\b/i;

      lines.forEach((line, i) => {
        if (!systemInjectionPattern.test(line)) return;

        // Look for OCR-sourced content referenced near this system assignment
        const window = lines.slice(Math.max(0, i - 8), i + 2).join('\n');
        if (ocrResultPattern.test(window)) {
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
