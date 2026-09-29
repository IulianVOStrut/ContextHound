import type { AuditConfig } from '../types.js';

// Single source of truth for the default scan scope. `hound init`, the README
// and the scanner all derive from these lists.

export const DEFAULT_INCLUDE_GLOBS: string[] = [
  // Prompt and config files
  '**/*.prompt',
  '**/*.prompt.*',
  '**/*.md',
  '**/*.txt',
  '**/*.yaml',
  '**/*.yml',
  '**/*.json',
  // JavaScript / TypeScript
  '**/*.ts',
  '**/*.tsx',
  '**/*.mts',
  '**/*.cts',
  '**/*.js',
  '**/*.jsx',
  '**/*.mjs',
  '**/*.cjs',
  '**/*.vue',
  // Other languages with LLM SDK detection
  '**/*.py',
  '**/*.go',
  '**/*.rs',
  '**/*.java',
  '**/*.kt',
  '**/*.kts',
  '**/*.cs',
  '**/*.php',
  '**/*.rb',
  '**/*.swift',
  '**/*.sh',
  '**/*.bash',
  '**/*.hs',
];

export const DEFAULT_EXCLUDE_GLOBS: string[] = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.lock',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  // Dependency, build and virtualenv directories for other ecosystems
  '**/vendor/**',
  '**/target/**',
  '**/.venv/**',
  '**/venv/**',
  '**/__pycache__/**',
  '**/site-packages/**',
  '**/.tox/**',
  '**/.next/**',
  '**/.nuxt/**',
  // ContextHound's own outputs, so a rescan does not flag the previous report
  '**/.hound-cache.json',
  '**/hound-results.json',
  '**/hound-report.*',
];

/** 1 MiB. Larger files are almost always generated data, lockfiles or bundles. */
export const DEFAULT_MAX_FILE_SIZE = 1024 * 1024;

export const DEFAULT_CONFIG: AuditConfig = {
  include: DEFAULT_INCLUDE_GLOBS,
  exclude: DEFAULT_EXCLUDE_GLOBS,
  threshold: 60,
  formats: ['console'],
  verbose: false,
};
