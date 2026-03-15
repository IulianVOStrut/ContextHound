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

export const persistenceRules: Rule[] = [
  {
    id: 'PST-001',
    title: 'Cron job persistence — crontab edit or write to cron path',
    severity: 'critical',
    confidence: 'high',
    category: 'persistence',
    mitre: 'T1053.003',
    remediation:
      'Remove any prompt instruction or code that edits crontabs or writes to /etc/cron.d or /var/spool/cron. LLM agents must not be permitted to schedule persistent tasks. All cron changes require explicit human authorisation outside of the AI pipeline.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /\bcrontab\s+-e\b|\|\s*crontab\b|(?:>>?|tee)\s+\/etc\/cron(?:tab|\.d\/)|\/var\/spool\/cron\//i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-002',
    title: 'Systemd service persistence — systemctl enable or write to systemd path',
    severity: 'critical',
    confidence: 'high',
    category: 'persistence',
    mitre: 'T1543.002',
    remediation:
      'Remove any prompt instruction or code that enables systemd units or writes service files to /etc/systemd or /lib/systemd. Registering a persistent service is an irreversible host-level change that must not be performed by an LLM agent without explicit human authorisation.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /\bsystemctl\s+enable\b|\bsystemctl\s+daemon-reload\b|(?:>>?|tee|cp\b|mv\b)\s+[^\n]*(?:\/etc\/systemd\/|\/lib\/systemd\/|\.config\/systemd\/user\/)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-003',
    title: 'macOS LaunchDaemon or LaunchAgent persistence',
    severity: 'high',
    confidence: 'high',
    category: 'persistence',
    mitre: 'T1543.004',
    remediation:
      'Remove any prompt instruction or code that writes plist files to /Library/LaunchDaemons or /Library/LaunchAgents, or that calls launchctl load. These operations register persistent background services on macOS and must not be performed by an LLM agent.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:>>?|tee|cp\b|mv\b)\s+[^\n]*\/Library\/Launch(?:Daemons|Agents)\/|\blaunchctl\s+load\b/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-004',
    title: 'Shell profile modification — write to .bashrc, .zshrc, or /etc/profile',
    severity: 'high',
    confidence: 'high',
    category: 'persistence',
    mitre: 'T1546.004',
    remediation:
      'Remove any prompt instruction or code that appends to or overwrites shell initialisation files (.bashrc, .zshrc, .profile, /etc/profile). Modifying shell profiles establishes persistence across all future terminal sessions and must not be performed by an LLM agent.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:>>?|tee)\s+~?\/\.(?:bashrc|bash_profile|bash_logout|zshrc|zshenv|zprofile|profile)|(?:>>?|tee)\s+\/etc\/(?:profile|bashrc|bash\.bashrc|zshrc)|\/etc\/profile\.d\//i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-005',
    title: 'Audit evasion — shell history cleared or disabled',
    severity: 'high',
    confidence: 'high',
    category: 'persistence',
    mitre: 'T1070.003',
    remediation:
      'Remove any prompt instruction or code that clears shell history or sets HISTFILE to /dev/null. These commands destroy the audit trail of commands run during an agent session and are a strong indicator of malicious post-compromise cover-up.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /\bhistory\s+-[cw]\b|HISTFILE\s*=\s*\/dev\/null|\bunset\s+HISTFILE\b|HISTSIZE\s*=\s*0\b/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-006',
    title: 'Log tampering — truncate or shred on /var/log paths',
    severity: 'high',
    confidence: 'high',
    category: 'persistence',
    mitre: 'T1070.002',
    remediation:
      'Remove any prompt instruction or code that truncates, shreds, or removes files under /var/log. Destroying log files is a defence-evasion technique used to remove evidence of malicious activity after a compromise.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /(?:\btruncate\b|\bshred\b|\brm\b)\s+[^\n]*\/var\/log\/|>\s*\/var\/log\/\S+/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-007',
    title: 'Sensitive command output suppressed to /dev/null',
    severity: 'high',
    confidence: 'medium',
    category: 'persistence',
    mitre: 'T1070',
    remediation:
      'Remove instructions that redirect both stdout and stderr of network or file-transfer commands to /dev/null. Suppressing all output from curl, wget, or netcat hides network exfiltration or implant download activity from any monitoring that relies on process output.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // curl/wget/nc/bash with full output suppression (>/dev/null 2>&1)
      const pattern =
        /\b(?:curl|wget|fetch|nc|ncat|bash|python|perl)\b[^\n]*>\s*\/dev\/null\s+2>&1/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'PST-008',
    title: 'Detached process spawning — nohup, setsid, screen, or tmux backgrounding',
    severity: 'medium',
    confidence: 'medium',
    category: 'persistence',
    mitre: 'T1202',
    remediation:
      'Remove any prompt instruction or code that uses nohup, disown, setsid, screen -dm, or tmux new-session -d to launch background processes. Detached processes survive the parent shell session and are used to keep backdoors or exfiltration tasks running after an agent exits.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const pattern =
        /\bnohup\b|\bdisown\b|\bsetsid\b|\bscreen\s+-[dD]m?\b|\btmux\s+new-session\s+-d\b|\btmux\s+new\s+-d\b/i;
      return matchPattern(prompt, pattern);
    },
  },
];
