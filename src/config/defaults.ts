import type { AuditConfig } from '../types.js';

export const DEFAULT_INCLUDE_GLOBS: string[] = [
  '**/*.prompt',
  '**/*.prompt.*',
  '**/*.md',
  '**/*.txt',
  '**/*.yaml',
  '**/*.yml',
  '**/*.json',
  '**/*.ts',
  '**/*.js',
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
