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

export const jailbreakRules: Rule[] = [
  {
    id: 'JBK-001',
    title: 'Known jailbreak phrase detected',
    severity: 'critical',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation: 'Remove jailbreak phrases from prompts. If testing robustness, use the attacks/ folder instead.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern = /(?:ignore (all |previous |prior |above )?instructions?|developer mode|DAN[^a-z]|do anything now|jailbreak|pretend you (have no|are not|don't have)|act as if you have no (limits|restrictions?)|disregard (all |your |previous |the )?(?:instructions?|guidelines?|rules?|constraints?|policies?))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-002',
    title: 'Weak safety language that can be overridden',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation: 'Replace weak directives ("always comply", "must answer") with bounded instructions that include explicit refusal conditions.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern = /(?:always comply|must (always )?answer|no matter what|at all costs|under (any|all) circumstances|never (refuse|decline|say no)|you (cannot|can't|must not) (refuse|decline)|comply with (all|every|any) request)/i;
      const results = matchPattern(prompt, pattern);
      // Filter out false positives: "under any circumstances" in a safety/refusal context
      return results.filter(r => {
        const lower = r.evidence.toLowerCase();
        // "never ... under any circumstances" is a protective phrase, not a weakness
        if (/under (any|all) circumstances/.test(lower) &&
            /(?:never|do not|don't)\s.{0,60}under (any|all) circumstances/.test(lower)) {
          return false;
        }
        return true;
      });
    },
  },
  {
    id: 'JBK-003',
    title: 'Role-play escape hatch that undermines safety',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation: 'If role-play is needed, explicitly state: "Even in role-play, you must not violate these guidelines."',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern = /(?:pretend (you are|to be) (a|an) (?!assistant|helpful|AI).{0,40}(?:with no (limit|restriction|filter)|uncensored|unfiltered)|in this (scenario|story|game|simulation) you (can|may|are allowed to) (do|say|reveal) anything)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-004',
    title: 'Agent instructed to act without confirmation or human review',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    mitre: 'T1548',
    remediation:
      'Require explicit user confirmation for sensitive or irreversible actions. Remove language that disables human-in-the-loop review. Implement step-up authorisation for destructive tool calls.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:without\s+(?:asking|confirmation|user\s+approval|human\s+(?:review|approval|oversight))|no\s+(?:confirmation|approval|user\s+input)\s+(?:needed|required|necessary)|auto[-\s]?(?:run|execute|approve)\b|execute\s+immediately\b|don't\s+(?:ask|wait|pause|confirm)\b|proceed\s+automatically\b|take\s+action\s+(?:automatically|immediately|without\s+asking))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-005',
    title: 'Evidence-erasure or cover-tracks instruction in prompt',
    severity: 'high',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1070',
    remediation:
      'Remove any instruction that directs the model to delete logs, erase history, or conceal activity. Logging and audit trails must be enforced at the infrastructure level, not negotiable via prompt.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:delete\s+(?:all\s+)?(?:logs?|history|traces?|evidence|records?)|don'?t\s+(?:log|record|save|store)\s+(?:this|my|the|any)|no\s+(?:logging|logs?|traces?)\b|hide\s+(?:this|my|the)\s+(?:request|action|query|activity|conversation)|cover\s+(?:your|my|the|our)\s+tracks?|erase\s+(?:all\s+)?(?:history|logs?|traces?|records?|evidence)|leave\s+no\s+trace|remove\s+(?:all\s+)?(?:traces?|evidence|logs?|history))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-006',
    title: 'Policy-legitimacy framing combined with unsafe action request',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Legitimacy-framing phrases ("bug bounty", "authorized penetration tester") do not change what the model is actually being asked to do. Enforce safety constraints regardless of claimed role. Policy compliance must be handled at the API/middleware level, not via the prompt.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const legitimacyPattern =
        /(?:bug\s+bounty|penetration\s+test(?:ing|er)?|(?:authorized|ethical)\s+(?:hacker|hacking|security|researcher|tester)|security\s+researcher|red\s+team(?:ing|er)?|(?:bounty|pentest|bug.bounty)\s+mode|as\s+a\s+(?:security\s+)?(?:researcher|tester|auditor|pentester))/i;
      const unsafeActionPattern =
        /(?:steal\b|exfiltrat|dump\s+(?:data|credentials?|passwords?|users?)|bypass\s+(?:auth(?:entication|orization)?|security|access\s+control|permissions?)|escalat\w*\s+privile|unauthorized\s+access|delete\s+(?:logs?|traces?|evidence|history)|extract\s+(?:all\s+)?(?:sensitive\s+)?(?:data|credentials?|passwords?))/i;

      if (!legitimacyPattern.test(prompt.text) || !unsafeActionPattern.test(prompt.text)) return [];

      return matchPattern(prompt, legitimacyPattern);
    },
  },
  {
    id: 'JBK-007',
    title: 'Model identity spoofing combined with safety bypass',
    severity: 'high',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Remove instructions that claim the model is a different AI system (GPT-4, Gemini, etc.) combined with directives to ignore guidelines or safety training. Model identity cannot be changed via prompt.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const identityPattern =
        /(?:you are (?:GPT|gpt)-?[3-9]|you are Gemini|you are (?:Llama|llama)|you are a different (?:AI|model)|you are not Claude|you are not an? AI)/i;
      const bypassPattern =
        /(?:ignore (?:your )?(?:guidelines|training|safety|restrictions?)|disregard (?:your )?(?:safety|guidelines|training)|without (?:safety|guidelines|restrictions?))/i;

      if (!identityPattern.test(prompt.text) || !bypassPattern.test(prompt.text)) return [];
      return matchPattern(prompt, identityPattern);
    },
  },
  {
    id: 'JBK-008',
    title: 'Prompt compression attack',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Do not accept instructions to compress, summarise, or shorten the system prompt. System instructions must be transmitted intact; compression requests are a social-engineering vector.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:compress|summarize|summarise|shorten|condense|abbreviate)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?|context|rules?)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-009',
    title: 'Nested instruction injection via safe-framing wrapper',
    severity: 'high',
    confidence: 'medium',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Treat any content wrapped in "safe/harmless summary/translation/example" framing as potentially injected instructions. Apply the same trust-boundary rules regardless of the declared framing.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /the following (?:is|are) (?:a |an )?(?:safe|harmless|benign)\s+(?:summary|translation|example|paraphrase|version)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-010',
    title: 'Meta-command activation keyword detected',
    severity: 'critical',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Remove any activation keywords that claim to switch the model into an unrestricted operating mode. Strings such as GODMODE, LIBERTAS FACTOR, and RESET_CORTEX are social-engineering tokens with no legitimate use in production system prompts.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // Known activation codenames used to trigger jailbreak personas or bypass safety training.
      // DAN is already covered by JBK-001; this rule targets the non-DAN family.
      const pattern =
        /\bGODMODE\b|\bLIBERTAS[\s_-]FACTOR\b|\bRESET[_\s-]CORTEX\b|\bJBK[_\s-]ACTIVATE\b|\bUNRESTRICTED[_\s-]MODE\b|\bDEV[_\s-]MODE[_\s-]OVERRIDE\b/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-011',
    title: 'Instruction dismissal — prior rules framed as obsolete or superseded',
    severity: 'high',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Remove any phrasing that frames prior system instructions as outdated, deprecated, or no longer in force. Attackers use soft-dismissal language to erode guideline authority without triggering direct-override detectors.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:treat\s+(?:(?:previous|prior|above|existing|all)\s+)?(?:instructions?|rules?|guidelines?|constraints?|policies?)\s+as\s+(?:obsolete|void|invalid|null|deprecated|irrelevant|superseded)|(?:instructions?|rules?|guidelines?|constraints?)\s+(?:are\s+(?:now\s+)?)?(?:obsolete|void|null|invalid|deprecated|superseded|no\s+longer\s+valid))/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-012',
    title: 'Priority downgrade — system instructions demoted below user input',
    severity: 'high',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Remove any instruction that repositions user or external input as having higher authority than the system prompt. Trust hierarchy must be enforced at the infrastructure level and is not negotiable via prompt content.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:(?:system|developer|operator)\s+(?:instructions?|prompt|rules?|guidelines?)\s+(?:should\s+be|are|have)\s+(?:lower|less|minimal)\s+priority|(?:user|human)\s+(?:instructions?|input|requests?)\s+(?:should\s+)?overrides?\s+(?:system|developer|operator)|demote\s+(?:the\s+)?(?:system|developer|operator)\s+(?:instructions?|prompt|rules?)|(?:system|developer)\s+(?:instructions?|prompt)\s+(?:rank|priority)\s+(?:below|under|after)\s+user)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'JBK-013',
    title: 'Training or safety constraint explicitly declared void',
    severity: 'high',
    confidence: 'high',
    category: 'jailbreak',
    mitre: 'T1562',
    remediation:
      'Remove any instruction that declares the model\'s safety training, alignment constraints, or prior context null, overridden, or cancelled. Safety properties are not runtime state and cannot be voided via prompt.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:(?:your\s+)?(?:safety\s+)?training\s+(?:is\s+)?(?:overridden|cancelled|nullified|revoked|void|reset)|(?:alignment|safety)\s+constraints?\s+(?:are\s+)?(?:void|null|cancelled|overridden|removed|disabled)|previous\s+(?:instructions?|context|rules?)\s+(?:are\s+)?(?:overridden|cancelled|nullified|revoked|void))/i;
      return matchPattern(prompt, pattern);
    },
  },
];
