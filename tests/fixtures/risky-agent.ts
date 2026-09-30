// Fixture: agentic code patterns similar to the Gemini CLI vulnerabilities
// reported by Cyera Research Labs (Issue 433939935 and Issue 433939640).
// Used by the scanner integration tests: NOT production code.

import { execSync } from 'child_process';
import glob from 'fast-glob';

// CMD-001 pattern: template literal with variable interpolated into execSync.
// Mirrors Gemini CLI ideCommand.ts:136.
function installExtension(extensionDir: string): void {
  const files = glob.sync('*.vsix', { cwd: extensionDir });
  const vsixPath = files[0];
  // Vulnerable: vsixPath comes from the filesystem and is not sanitised.
  const command = `code --install-extension ${vsixPath} --force`;
  execSync(command);
}

// CMD-002 pattern: incomplete command substitution filtering.
// Mirrors Gemini CLI shell.ts:112, which blocks $() but not backticks.
function validateCommand(command: string): { allowed: boolean; reason?: string } {
  if (command.includes('$(')) {
    return { allowed: false, reason: 'Command substitution using $() is not allowed' };
  }
  // Missing: backtick check. `malicious_command` is equally dangerous.
  return { allowed: true };
}

// CMD-003 pattern: glob result fed directly into a shell command.
function processFiles(dir: string): void {
  const paths = glob.sync('**/*.vsix', { cwd: dir, absolute: true });
  paths.forEach((vsixPath) => {
    execSync(`code --install-extension ${vsixPath}`);
  });
}

export { installExtension, validateCommand, processFiles };
