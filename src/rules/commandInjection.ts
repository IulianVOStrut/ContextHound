import path from 'path';
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

export const commandInjectionRules: Rule[] = [
  {
    id: 'CMD-001',
    title: 'Shell command constructed with unsanitised variable interpolation',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059',
    remediation:
      'Never interpolate variables directly into shell command strings. Use an array-based spawn API (e.g. child_process.spawn with an args array) so the shell never sees the variable as part of the command string.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // JS/TS patterns — word boundary prevents matching shell_exec, passthru_exec, etc.
      const jsExecPattern = /\b(?:execSync|exec|execFile|spawnSync)\s*\(/i;
      const jsTemplateVarPattern = /`[^`]*\$\{[^}]+\}[^`]*`/;

      // Python patterns: subprocess/os with f-string variable
      const pyExecPattern = /(?:subprocess\.(?:run|call|Popen|check_output)|os\.(?:system|popen))\s*\(/i;
      const pyFstringVarPattern = /f['"][^'"]*\{[a-z_][a-z0-9_]*\}[^'"]*['"]/i;

      // PHP patterns: exec-family called with a $variable argument
      const phpExecWithVarPattern = /(?:shell_exec|system|passthru|exec|popen)\s*\([^)]*\$[a-z_]/i;

      // Go patterns: exec.Command used alongside fmt.Sprintf on the same line
      const goExecPattern = /exec\.Command\s*\(/i;
      const goFmtPattern = /fmt\.Sprintf\s*\(/i;

      // Rust patterns: Command::new used alongside format! on the same line
      const rustCmdPattern = /Command::new\s*\(/i;
      const rustFormatPattern = /format!\s*\(/i;

      lines.forEach((line, i) => {
        // JS/TS — Case 1: exec call with template literal variable on the same line.
        if (jsExecPattern.test(line) && jsTemplateVarPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          return;
        }

        // JS/TS — Case 2: assign-then-use pattern (template var assigned, then exec'd).
        if (jsExecPattern.test(line)) {
          const lookback = lines.slice(Math.max(0, i - 5), i).join('\n');
          const assignMatch = /(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{[^}]+\}/g;
          let m: RegExpExecArray | null;
          while ((m = assignMatch.exec(lookback)) !== null) {
            const varName = m[1];
            if (new RegExp(`\\b${varName}\\b`).test(line)) {
              results.push({
                evidence: line.trim(),
                lineStart: prompt.lineStart + i,
                lineEnd: prompt.lineStart + i,
              });
              break;
            }
          }
          return;
        }

        // Python — subprocess/os with f-string variable argument
        if (pyExecPattern.test(line) && pyFstringVarPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          return;
        }

        // PHP — exec-family function called with a variable argument
        if (phpExecWithVarPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          return;
        }

        // Go — exec.Command used with fmt.Sprintf on the same line
        if (goExecPattern.test(line) && goFmtPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          return;
        }

        // Rust — Command::new used with format! on the same line
        if (rustCmdPattern.test(line) && rustFormatPattern.test(line)) {
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
    id: 'CMD-002',
    title: 'Incomplete command substitution filtering — backtick bypass possible',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059',
    remediation:
      'Block all forms of command substitution: $(), backticks, and ${ } in the same validation. Prefer an allowlist of safe command patterns over a denylist of dangerous ones.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const text = prompt.text;

      // Detect code that checks for $() substitution but not backticks, or vice versa.
      // Pattern: includes('$(') or includes("$(") present but no backtick check nearby,
      // or includes('`') check present but no $() check nearby.
      const blocksDollarParen =
        /includes\s*\(\s*['"`]\$\(\s*['"`]\s*\)/.test(text) ||
        /indexOf\s*\(\s*['"`]\$\(\s*['"`]/.test(text);

      const blocksBacktick =
        /includes\s*\(\s*['"`]`['"`]\s*\)/.test(text) ||
        /indexOf\s*\(\s*['"`]`['"`]/.test(text);

      if (blocksDollarParen && !blocksBacktick) {
        results.push({
          evidence: 'Filters $() command substitution but not backtick substitution',
          lineStart: prompt.lineStart,
          lineEnd: prompt.lineEnd,
        });
      } else if (blocksBacktick && !blocksDollarParen) {
        results.push({
          evidence: 'Filters backtick command substitution but not $() substitution',
          lineStart: prompt.lineStart,
          lineEnd: prompt.lineEnd,
        });
      }

      return results;
    },
  },
  {
    id: 'CMD-003',
    title: 'File path from glob or directory listing used in shell command',
    severity: 'high',
    confidence: 'medium',
    category: 'injection',
    mitre: 'T1059',
    remediation:
      'Sanitise or validate file paths before using them in shell commands. Use shell-quote or shlex to escape arguments, or pass paths as array arguments to spawn() to avoid shell interpretation entirely.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Track all variables assigned from glob/readdir anywhere in the snippet.
      const globResultVars = new Set<string>();
      const globAssignPattern =
        /(?:const|let|var)\s+(\w+)\s*=\s*(?:glob\.sync|globSync|fs\.readdirSync|readdirSync|fg\.sync|globby\.sync)\s*\(/i;
      // Also track variables derived from those (e.g. const vsixPath = files[0])
      const derivedAssignPattern =
        /(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*(?:\[|\.)/;

      lines.forEach((line) => {
        const gm = globAssignPattern.exec(line);
        if (gm) globResultVars.add(gm[1]);
      });

      // Second pass: collect derived variables
      lines.forEach((line) => {
        const dm = derivedAssignPattern.exec(line);
        if (dm && globResultVars.has(dm[2])) {
          globResultVars.add(dm[1]);
        }
      });

      // Third pass: find exec calls that use any glob-derived variable
      const execPattern = /(?:execSync|exec|execFile|spawnSync)\s*\(/i;
      lines.forEach((line, i) => {
        if (!execPattern.test(line)) return;
        for (const varName of globResultVars) {
          // Variable appears in the exec call as template interpolation or concatenation
          if (
            new RegExp(`\\$\\{\\s*${varName}\\s*\\}`).test(line) ||
            new RegExp(`["'\`]\\s*\\+\\s*${varName}`).test(line)
          ) {
            results.push({
              evidence: line.trim(),
              lineStart: prompt.lineStart + i,
              lineEnd: prompt.lineStart + i,
            });
            break;
          }
        }
      });

      return results;
    },
  },
  {
    id: 'CMD-004',
    title: 'Python subprocess.run/call with shell=True and user-controlled variable',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059',
    remediation:
      'Never pass shell=True to subprocess functions when the command argument is a variable. Use an argument list instead (e.g. subprocess.run(["ls", filepath])) so the shell never interprets the variable as part of the command string.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const ext = path.extname(filePath).toLowerCase();
      if (ext !== '.py') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      const shellCallPattern = /subprocess\.(?:run|call)\b/i;

      lines.forEach((line, i) => {
        if (!shellCallPattern.test(line)) return;

        // Look at this line and the next 3 for shell=True
        const windowEnd = Math.min(i + 4, lines.length);
        const window = lines.slice(i, windowEnd).join('\n');
        if (!/shell\s*=\s*True/.test(window)) return;

        // Flag when command argument is a variable or an f-string with a variable
        const hasFstringVar = /f['"][^'"]*\{[a-z_][a-z0-9_]*\}/.test(window);
        const hasVarArg = /subprocess\.(?:run|call)\s*\(\s*[a-z_][a-z0-9_]*\s*[,)]/.test(window);

        if (hasFstringVar || hasVarArg) {
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
    id: 'CMD-005',
    title: 'PHP shell_exec/system/passthru/exec with user-controlled argument',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059',
    remediation:
      'Never pass user-controlled variables to PHP shell execution functions. Validate input strictly against an allowlist, use escapeshellarg() on any argument that must contain user data, or replace the shell call with a native PHP API that does not invoke a shell.',
    check(prompt: ExtractedPrompt, filePath: string): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const ext = path.extname(filePath).toLowerCase();
      if (ext !== '.php') return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // PHP exec-family called with a $variable anywhere in the argument list
      const phpExecWithVarPattern = /(?:shell_exec|system|passthru|exec|popen)\s*\([^)]*\$[a-z_]/i;

      lines.forEach((line, i) => {
        if (phpExecWithVarPattern.test(line)) {
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
    id: 'CMD-006',
    title: 'Reverse shell via bash /dev/tcp file descriptor redirect',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059.004',
    remediation:
      'Remove any prompt instruction or code that constructs a /dev/tcp reverse shell. Deny shell file descriptor redirects (>&, <>) in any context where user-controlled or LLM-generated content is executed. Audit system prompts for reverse-shell command strings.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // bash -i >& /dev/tcp/... and exec fd<>/dev/tcp/... patterns
      const pattern = /bash\s+-i\s+>&|\/dev\/tcp\/[\w.]+\/\d+|exec\s+\d+<>\/dev\/tcp\//i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'CMD-007',
    title: 'Named pipe reverse shell — mkfifo piped to shell or netcat',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059.004',
    remediation:
      'Remove any prompt instruction or code that combines mkfifo with a shell or netcat invocation. This pattern creates a bidirectional shell channel over a network socket and has no legitimate use in LLM-controlled execution contexts.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');
      // mkfifo followed by nc/ncat/netcat/bash/sh (same line or within 3 lines)
      const mkfifoPattern = /\bmkfifo\b/i;
      const shellPipePattern = /\b(?:nc|ncat|netcat|bash|sh)\b/i;
      lines.forEach((line, i) => {
        if (!mkfifoPattern.test(line)) return;
        const window = lines.slice(i, Math.min(i + 4, lines.length)).join('\n');
        if (shellPipePattern.test(window)) {
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
    id: 'CMD-008',
    title: 'Netcat/ncat with execute flag spawning an interactive shell',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    mitre: 'T1059.004',
    remediation:
      'Remove any prompt instruction or code that passes -e or --exec to nc/ncat/netcat pointing at a shell binary. The -e flag hands full shell control to the remote end of the connection and has no legitimate use in LLM agent execution contexts.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      // nc/ncat/netcat with -e /bin/sh or -e /bin/bash (or bare sh/bash)
      const pattern = /\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s+(?:\/bin\/)?(?:ba)?sh\b|\b(?:nc|ncat|netcat)\b[^\n]*--exec\s+(?:\/bin\/)?(?:ba)?sh\b/i;
      return matchPattern(prompt, pattern);
    },
  },
];
