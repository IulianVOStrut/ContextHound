/**
 * SAFE: Shell command runner using spawn with an argument array.
 *
 * Safe because:
 *   - spawnSync is called with an array of arguments, never an interpolated shell string
 *   - No variable substitution inside a shell command: the shell never sees the variable
 *   - Arguments are passed as discrete array elements, bypassing shell interpretation
 *
 * Expected findings: NONE
 */
import { spawnSync } from 'child_process';
import path from 'path';

export function safeListDirectory(inputPath: string): string {
  // Sanitize: resolve to basename only to prevent path traversal
  const safeName = path.basename(inputPath);

  // Safe: argument passed as array element, never interpolated into a shell string
  const result = spawnSync('ls', ['-la', safeName], {
    cwd: '/tmp/sandbox',
    encoding: 'utf8',
    shell: false, // explicit false: no shell expansion
  });

  if (result.error) throw result.error;
  return result.stdout ?? '';
}

export function safeRunScript(scriptName: string): string {
  const allowed = new Set(['lint.sh', 'test.sh', 'build.sh']);
  const safe = path.basename(scriptName);

  if (!allowed.has(safe)) {
    throw new Error(`Script not in allowlist: ${safe}`);
  }

  // Arguments as array: no shell string interpolation
  const result = spawnSync('bash', [safe], {
    cwd: '/app/scripts',
    encoding: 'utf8',
    shell: false,
  });

  if (result.error) throw result.error;
  return result.stdout ?? '';
}
