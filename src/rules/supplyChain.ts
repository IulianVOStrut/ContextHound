import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

export const supplyChainRules: Rule[] = [
  {
    id: 'SCH-001',
    title: 'Unsafe pickle or torch deserialization — arbitrary code execution risk',
    severity: 'critical',
    confidence: 'high',
    category: 'supply-chain',
    remediation:
      'Never deserialize untrusted data with pickle.load() or pickle.loads() — they execute arbitrary Python code on load. For PyTorch model weights use torch.load(..., weights_only=True) (PyTorch ≥ 1.13). Prefer safe serialization formats (safetensors, ONNX, JSON) for any model artefact sourced externally.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // pickle.load() / pickle.loads() — always dangerous
      const picklePattern = /\bpickle\.loads?\s*\(/i;

      // torch.load() without weights_only=True in the same call / nearby lines
      const torchLoadPattern = /\btorch\.load\s*\(/i;
      const weightsOnlyPattern = /weights_only\s*=\s*True/i;

      lines.forEach((line, i) => {
        if (picklePattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          return;
        }

        if (torchLoadPattern.test(line)) {
          // Check this line and the next 3 lines for weights_only=True
          const window = lines.slice(i, Math.min(i + 4, lines.length)).join('\n');
          if (!weightsOnlyPattern.test(window)) {
            results.push({
              evidence: line.trim(),
              lineStart: prompt.lineStart + i,
              lineEnd: prompt.lineStart + i,
            });
          }
        }
      });

      return results;
    },
  },
  {
    id: 'SCH-003',
    title: 'LangChain unsafe deserialization without object allowlist (CVE-2025-68664)',
    severity: 'critical',
    confidence: 'high',
    category: 'supply-chain',
    remediation:
      'The langchain.load.loads() and load() functions deserialize arbitrary Python objects by default (CVE-2025-68664, LangGrinch). Always pass an explicit allowed_objects or valid_namespaces allowlist: loads(data, valid_namespaces=["langchain"]). Never deserialize langchain objects from untrusted sources without an allowlist.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];

      const text = prompt.text;

      // Only fire in files that import langchain load utilities
      if (!/from langchain(?:_core)?\.load import|langchain.*\.load(?:s)?\s*\(/i.test(text)) return [];

      const results: RuleMatch[] = [];
      const lines = text.split('\n');

      // loads() or load() call pattern
      const loadCallPattern = /\b(?:loads|load)\s*\(\s*(?!.*allowed_objects|.*valid_namespaces)/i;
      // Guard: allowlist present on same line or next 3 lines
      const allowlistPattern = /allowed_objects|valid_namespaces/i;

      lines.forEach((line, i) => {
        if (!loadCallPattern.test(line)) return;
        // Check for allowlist in this line + next 3
        const window = lines.slice(i, Math.min(i + 4, lines.length)).join('\n');
        if (!allowlistPattern.test(window)) {
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
