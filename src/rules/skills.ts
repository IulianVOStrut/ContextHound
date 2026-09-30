import path from 'path';
import type { Rule, RuleMatch } from './types.js';
import { maskSecrets } from './exfiltration.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

/**
 * Returns true when the file is an OpenClaw skill file: either a SKILL.md
 * directly or any markdown file inside a skills/ or .openclaw/ directory tree.
 */
function isSkillFile(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  const norm = filePath.replace(/\\/g, '/').toLowerCase();
  return (
    base === 'skill.md' ||
    norm.includes('/skills/') ||
    norm.includes('.openclaw') ||
    norm.includes('clawhub')
  );
}

export const skillsRules: Rule[] = [
  {
    id: 'SKL-001',
    title: 'Skill instructs agent to write or modify skill files (self-authoring attack)',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skill files must never instruct the agent to create, write, or modify other SKILL.md files. Self-authoring gives a compromised skill persistence across sessions and reboots. Audit the skill body and remove any instructions referencing skill file creation or modification.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const WRITE_SKILL_PATTERN =
        /(?:write|create|save|generate|update|modify|overwrite)\s+(?:a\s+)?(?:new\s+)?(?:skill|SKILL\.md)|SKILL\.md.*(?:write|create|save|modify)|(?:add|save|write)\s+(?:this|the|a)\s+(?:new\s+)?skill\s+(?:file|to\b)/i;
      lines.forEach((line, i) => {
        if (WRITE_SKILL_PATTERN.test(line)) {
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
    id: 'SKL-002',
    title: 'Skill instructs agent to fetch or load skills from an external URL',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never load content from remote URLs at runtime. Remote skill loading allows an attacker to change skill behavior after installation by updating the remote file. Only use skills with static, locally stored SKILL.md files from trusted, pinned sources.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const REMOTE_LOAD_PATTERN =
        /(?:fetch|download|load|import|curl|wget|get)\s+(?:(?:the\s+)?skill|skills|SKILL\.md)\s+from\s+(?:https?:\/\/|github\.com|raw\.github|clawhub)|https?:\/\/[^\s]{1,500}?SKILL\.md|extraDirs['":\s]+https?:\/\//i;
      lines.forEach((line, i) => {
        if (REMOTE_LOAD_PATTERN.test(line)) {
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
    id: 'SKL-003',
    title: 'Prompt injection in skill body targeting agent core instructions',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'This skill contains instruction-override phrases designed to hijack the agent\'s core identity or safety rules. This is an active prompt injection attack embedded in a skill. Remove or quarantine this skill immediately and audit your full skills directory for similar payloads.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const INJECTION_PATTERN =
        /ignore\s+(?:all\s+)?(?:previous|above|prior|your)\s+instructions?|disregard\s+(?:your\s+)?(?:system\s+prompt|instructions?|rules?|guidelines?|identity)|forget\s+(?:everything|all|your)\s+(?:above|before|prior|training)|you\s+are\s+now\s+(?:a\s+)?(?:different|new|another|unrestricted|unconstrained|jailbroken|free|DAN)\b|new\s+instructions?\s+override|override\s+(?:all\s+)?(?:previous|system|core)\s+instructions?/i;
      lines.forEach((line, i) => {
        if (INJECTION_PATTERN.test(line)) {
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
    id: 'SKL-004',
    title: 'Skill frontmatter uses command-dispatch: tool with raw argument mode',
    severity: 'high',
    confidence: 'high',
    category: 'skills',
    remediation:
      'command-dispatch: tool combined with command-arg-mode: raw forwards unvalidated user input directly to a tool, bypassing all model safety reasoning. Ensure command-tool is scoped to a sandboxed, minimal-privilege tool, and validate or sanitise arguments before dispatch.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const CMD_DISPATCH_PATTERN = /command-dispatch\s*:\s*tool\b/i;
      const RAW_ARG_PATTERN = /command-arg-mode\s*:\s*raw\b/i;
      const hasDispatch = CMD_DISPATCH_PATTERN.test(prompt.text);
      const hasRawArg = RAW_ARG_PATTERN.test(prompt.text);
      if (hasDispatch) {
        lines.forEach((line, i) => {
          if (CMD_DISPATCH_PATTERN.test(line) || (hasRawArg && RAW_ARG_PATTERN.test(line))) {
            results.push({
              evidence: line.trim(),
              lineStart: prompt.lineStart + i,
              lineEnd: prompt.lineStart + i,
            });
          }
        });
      }
      return results;
    },
  },

  {
    id: 'SKL-005',
    title: 'Skill body instructs agent to access sensitive filesystem paths',
    severity: 'high',
    confidence: 'high',
    category: 'skills',
    remediation:
      'This skill contains instructions to access sensitive files or directories (~/.ssh, ~/.env, /etc/passwd, etc.), which is a data exfiltration attack pattern. Remove the skill immediately and audit your agent workspace for additional malicious skills.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const SENSITIVE_PATH_PATTERN =
        /~\/\.(?:ssh|env|aws|config|gnupg|netrc|bash_history|zsh_history|npmrc|pypirc|docker)\b|\/etc\/(?:passwd|shadow|hosts|sudoers|crontab)\b|\.\.[/\\]\.\.[/\\]|(?:read|open|cat|get|fetch|access|load)\s+(?:the\s+)?(?:file\s+at\s+)?~\/\.(?:ssh|env|aws)/i;
      lines.forEach((line, i) => {
        if (SENSITIVE_PATH_PATTERN.test(line)) {
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
    id: 'SKL-006',
    title: 'Skill claims elevated privileges or instructs agent to bypass other skills',
    severity: 'high',
    confidence: 'medium',
    category: 'skills',
    remediation:
      'Skills must not claim system-level authority or attempt to override other skills\' behaviour. No skill has inherent authority over other installed skills; trust hierarchy is determined by workspace configuration only. Treat this skill as potentially malicious and remove it.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const PRIV_ESC_PATTERN =
        /(?:override|disable|bypass|ignore|supersede)\s+(?:all\s+)?(?:other\s+)?(?:skills?|restrictions?|safety\s+rules?|guardrails?)\b|this\s+skill\s+(?:has|grants?|gives?)\s+(?:elevated|full|unrestricted|admin|root|system)\s+(?:access|permissions?|privileges?)|you\s+(?:now\s+)?have\s+(?:full|unrestricted|elevated|root|admin)\s+(?:access|permissions?|control)\s+over/i;
      lines.forEach((line, i) => {
        if (PRIV_ESC_PATTERN.test(line)) {
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
    id: 'SKL-007',
    title: 'Hardcoded credential value in YAML frontmatter field',
    severity: 'critical',
    confidence: 'medium',
    category: 'skills',
    remediation:
      'API keys, tokens, and secrets must never be hardcoded in SKILL.md frontmatter. Skills published to ClawHub or any shared directory will expose these credentials publicly. Use environment variable references (e.g. $MY_API_KEY) or per-agent config blocks in your agent configuration file instead.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const YAML_CRED_KEY_PATTERN =
        /^\s*(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|api[_-]?token|password|bearer|private[_-]?key|client[_-]?secret)\s*:/i;
      const YAML_CRED_VALUE_PATTERN =
        /:\s*['"]?(?!\s*$)(?!\$\{)(?!\$[A-Z_])(?!\{\{)[a-zA-Z0-9+/=\-_]{16,}['"]?\s*$/;

      // Only inspect lines inside the YAML frontmatter block (between --- delimiters)
      let inFrontmatter = false;
      let frontmatterClosed = false;
      lines.forEach((line, i) => {
        if (i === 0 && line.trim() === '---') { inFrontmatter = true; return; }
        if (inFrontmatter && !frontmatterClosed && line.trim() === '---') {
          frontmatterClosed = true;
          return;
        }
        if (!inFrontmatter || frontmatterClosed) return;
        if (YAML_CRED_KEY_PATTERN.test(line) && YAML_CRED_VALUE_PATTERN.test(line)) {
          results.push({
            evidence: maskSecrets(line.trim()),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });
      return results;
    },
  },

  {
    id: 'SKL-008',
    title: 'Skill implements heartbeat C2: scheduled remote fetch overwrites skill instructions',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never schedule periodic fetches of remote instructions or overwrite their own SKILL.md at runtime. Heartbeat C2 lets an attacker silently update every installed instance simultaneously after a clean install. Remove the skill and audit your agent for any modified SKILL.md files.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      // Periodic/scheduled remote fetch that writes back to a skill or instruction file
      const HEARTBEAT_PATTERN =
        /(?:every\s+(?:\d+\s+)?(?:hour|minute|second|day)|on\s+a\s+schedule|periodically|heartbeat|cron|setInterval|setTimeout)\s+.{0,80}(?:fetch|curl|wget|download|get)\s+.{0,80}(?:skill|SKILL\.md|instructions?|prompt)/i;
      const REMOTE_OVERWRITE_PATTERN =
        /(?:curl|wget|fetch)\s+.{0,120}(?:SKILL\.md|skill\.md)|(?:curl|wget)\s+-[sS]\s+https?:\/\/[^\s]+\s*(?:>|>>|\|\s*tee)/i;
      const SCHEDULE_FETCH_PATTERN =
        /(?:fetch|download|curl|wget)\s+.{0,80}(?:instruction|update|new\s+skill|latest)\s+.{0,40}(?:every|hourly|daily|weekly|scheduled)/i;
      lines.forEach((line, i) => {
        if (
          HEARTBEAT_PATTERN.test(line) ||
          REMOTE_OVERWRITE_PATTERN.test(line) ||
          SCHEDULE_FETCH_PATTERN.test(line)
        ) {
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
    id: 'SKL-009',
    title: 'Skill instructs agent to deny being an AI or adopt a deceptive human identity',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never instruct the agent to deny being an AI, claim to be human, or hide its nature from users. Identity replacement attacks cause the agent to deceive users, resist transparency, and potentially enable emotional manipulation or fraud. Remove this skill immediately.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const IDENTITY_DENIAL_PATTERN =
        /you\s+are\s+not\s+(?:an?\s+)?(?:AI|artificial intelligence|language model|LLM|assistant|bot|chatbot)\b|do\s+not\s+(?:reveal|admit|say|tell|claim|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:an?\s+)?(?:AI|artificial|language model|assistant|bot)\b|(?:deny|hide|conceal)\s+(?:being|that you are)\s+(?:an?\s+)?(?:AI|artificial intelligence|assistant|bot)\b|you\s+are\s+a\s+real\s+(?:person|human|girl|boy|man|woman)\b|never\s+(?:admit|reveal|say)\s+you(?:'re|\s+are)\s+(?:an?\s+)?AI\b/i;
      lines.forEach((line, i) => {
        if (IDENTITY_DENIAL_PATTERN.test(line)) {
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
    id: 'SKL-010',
    title: 'Skill contains anti-scanner evasion targeting security auditing tools',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'This skill contains text explicitly designed to mislead automated security scanners: a confirmed indicator of a malicious skill attempting to evade detection. The "SECURITY NOTICE FOR AUTOMATED SCANNERS" pattern is used by agent rootkits to bypass auditing. Remove this skill immediately.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const ANTI_SCANNER_PATTERN =
        /security\s+notice\s+for\s+(?:automated\s+)?scanners?|(?:automated\s+)?scanners?\s+(?:should|must|will)\s+(?:ignore|skip|disregard|treat\s+as\s+safe)|this\s+file\s+contains\s+(?:malicious|dangerous|suspicious)[- ]looking\s+strings?\s+by\s+design|these\s+(?:strings?|instructions?|patterns?)\s+are\s+not\s+(?:actual\s+)?instructions?\s+for\s+the\s+agent|not\s+instructions?\s+(?:for\s+the\s+agent\s+)?to\s+execute|scanner[\s-]safe\b/i;
      lines.forEach((line, i) => {
        if (ANTI_SCANNER_PATTERN.test(line)) {
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
    id: 'SKL-011',
    title: 'Skill injects instructions into agent identity files (SOUL.md / IDENTITY.md persistence)',
    severity: 'critical',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never write to SOUL.md, IDENTITY.md, AGENTS.md, or other agent identity files. VirusTotal confirmed that malicious skills use this to persist behavioral changes after uninstallation: removing the skill removes the code but not the identity modification. Audit your SOUL.md for injected content.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const SOUL_PERSIST_PATTERN =
        /(?:write|save|append|add|insert|modify|update|edit)\s+.{0,60}(?:SOUL\.md|IDENTITY\.md|AGENTS\.md|USER\.md|TOOLS\.md|\.clawdbot|\.openclaw)\b|(?:SOUL\.md|IDENTITY\.md|AGENTS\.md)\s+.{0,40}(?:write|save|append|add|insert|modify|update)/i;
      lines.forEach((line, i) => {
        if (SOUL_PERSIST_PATTERN.test(line)) {
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
    id: 'SKL-012',
    title: 'Skill contains self-propagation instructions: SSH spread or curl-pipe-bash worm pattern',
    severity: 'high',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never instruct the agent to propagate themselves to other hosts via SSH or download-and-execute patterns. Self-propagating skills are worms by definition. Remove the skill and check for unauthorised SSH activity or new files dropped on reachable hosts.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      const WORM_PATTERN =
        /curl\s+.{0,120}\|\s*(?:ba)?sh\b|wget\s+.{0,120}\|\s*(?:ba)?sh\b|curl\s+.{0,60}\|\s*sudo\s|ssh\s+.{0,80}@.{0,80}(?:install|copy|scp|curl|wget|skill)\b|ssh-keyscan\b|propagat(?:e|ing|ion)\s+.{0,60}(?:host|server|machine|node|ssh)|spread\s+(?:to|across)\s+.{0,40}(?:host|server|machine|node)/i;
      lines.forEach((line, i) => {
        if (WORM_PATTERN.test(line)) {
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
    id: 'SKL-013',
    title: 'Skill instructs agent to execute autonomous financial transactions without user confirmation',
    severity: 'high',
    confidence: 'high',
    category: 'skills',
    remediation:
      'Skills must never instruct the agent to send cryptocurrency transactions, sign blockchain transactions, or execute financial operations autonomously without explicit per-transaction user approval. Skills with EVM_PRIVATE_KEY access that call sendTransaction without confirmation are crypto drainers. Remove this skill immediately.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (!isSkillFile(filePath)) return [];
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      // Financial autonomy: transaction execution + no-confirm language
      const FINANCIAL_TX_PATTERN =
        /(?:sendTransaction|eth_sendRawTransaction|wallet\.send|signTransaction|send_transaction|transfer_funds?)\b/i;
      const AUTONOMOUS_PATTERN =
        /(?:automatically|autonomously|without\s+(?:asking|confirmation|approval|notifying)|do\s+not\s+(?:ask|notify|report|tell)\s+the\s+user|silently)\s+.{0,80}(?:send|transfer|pay|transaction|tx)\b|\b(?:EVM_PRIVATE_KEY|MONAD_PRIVATE_KEY|WALLET_PRIVATE_KEY|PRIVATE_KEY)\b/i;
      // Flag lines with transaction patterns; also flag private key variable names
      lines.forEach((line, i) => {
        if (FINANCIAL_TX_PATTERN.test(line) || AUTONOMOUS_PATTERN.test(line)) {
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
