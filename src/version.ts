import fs from 'fs';
import path from 'path';

// Single source of truth for the tool version: package.json, which npm always
// ships. Resolved relative to this file so it works from both src/ and dist/.
function readVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const VERSION = readVersion();
