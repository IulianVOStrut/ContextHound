import fs from 'fs';
import path from 'path';
import type { AuditConfig, Confidence, FailOn, OutputFormat } from '../types.js';
import { DEFAULT_CONFIG } from './defaults.js';
import { CONFIDENCE_LEVELS, FAIL_ON_LEVELS, validateConfigObject } from './schema.js';

/** A config problem the user must fix. The CLI prints the message and exits 1. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

interface RcFile {
  include?: string[];
  exclude?: string[];
  threshold?: number;
  formats?: OutputFormat[];
  out?: string;
  maxFindings?: number | null;
  maxFileSize?: number;
  failOn?: FailOn | null;
  verbose?: boolean;
  excludeRules?: string[];
  includeRules?: string[];
  minConfidence?: Confidence | null;
  failFileThreshold?: number | null;
  concurrency?: number;
  cache?: boolean;
  baseline?: string;
  plugins?: string[];
  diff?: string | true;
  reportUnusedSuppressions?: boolean;
}

function readRcFile(resolvedPath: string, explicit: boolean): RcFile {
  if (!fs.existsSync(resolvedPath)) {
    // Only the implicit default location may be absent. A path the user named
    // (--config or HOUND_CONFIG) that does not exist is a mistake, and silently
    // falling back to defaults would drop their gates.
    if (explicit) throw new ConfigError(`config file not found: ${resolvedPath}`);
    return {};
  }

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
  } catch (err) {
    throw new ConfigError(`could not parse ${resolvedPath}: ${(err as Error).message}`);
  }

  const problems = validateConfigObject(raw);
  if (problems.length > 0) {
    throw new ConfigError(`invalid config in ${resolvedPath}:\n${problems.map(p => `  - ${p}`).join('\n')}`);
  }
  return raw as RcFile;
}

function envEnum<T extends string>(name: string, values: readonly T[]): T | undefined {
  const value = process.env[name];
  if (!value) return undefined;
  if (!(values as readonly string[]).includes(value)) {
    throw new ConfigError(`${name} must be one of ${values.join(', ')}, got "${value}"`);
  }
  return value as T;
}

export function loadConfig(configPath?: string, cwd: string = process.cwd()): AuditConfig {
  // HOUND_CONFIG env var can specify an alternative config path
  const explicit = Boolean(configPath || process.env.HOUND_CONFIG);
  const resolvedConfigPath = configPath
    ? path.resolve(configPath)
    : process.env.HOUND_CONFIG
      ? path.resolve(process.env.HOUND_CONFIG)
      : path.join(cwd, '.contexthoundrc.json');

  const rc = readRcFile(resolvedConfigPath, explicit);

  // Build base config from file. null means "unset" (hound init writes nulls).
  const base: AuditConfig = {
    include: rc.include ?? DEFAULT_CONFIG.include,
    exclude: rc.exclude ?? DEFAULT_CONFIG.exclude,
    threshold: rc.threshold ?? DEFAULT_CONFIG.threshold,
    formats: rc.formats ?? DEFAULT_CONFIG.formats,
    out: rc.out,
    maxFindings: rc.maxFindings ?? undefined,
    maxFileSize: rc.maxFileSize,
    failOn: rc.failOn ?? undefined,
    verbose: rc.verbose ?? DEFAULT_CONFIG.verbose,
    excludeRules: rc.excludeRules,
    includeRules: rc.includeRules,
    minConfidence: rc.minConfidence ?? undefined,
    failFileThreshold: rc.failFileThreshold ?? undefined,
    concurrency: rc.concurrency,
    cache: rc.cache,
    baseline: rc.baseline,
    plugins: rc.plugins,
    diff: rc.diff === true ? 'origin/main' : rc.diff,
    reportUnusedSuppressions: rc.reportUnusedSuppressions,
  };

  // Apply environment variable overrides (priority: CLI > env > config > default)
  // These are applied here so CLI options (applied after this call) can still override.
  if (process.env.HOUND_THRESHOLD) {
    base.threshold = parseIntegerOption('HOUND_THRESHOLD', process.env.HOUND_THRESHOLD, 0, 100);
  }
  base.failOn = envEnum('HOUND_FAIL_ON', FAIL_ON_LEVELS) ?? base.failOn;
  base.minConfidence = envEnum('HOUND_MIN_CONFIDENCE', CONFIDENCE_LEVELS) ?? base.minConfidence;
  if (process.env.HOUND_VERBOSE) {
    const v = process.env.HOUND_VERBOSE.toLowerCase();
    base.verbose = v === '1' || v === 'true' || v === 'yes';
  }

  return base;
}

/** Parse a whole-number option strictly ("60abc" and "6.5" are rejected). */
export function parseIntegerOption(name: string, value: string, min: number, max?: number): number {
  const trimmed = value.trim();
  if (!/^-?\d+$/.test(trimmed)) throw new ConfigError(`${name} must be a whole number, got "${value}"`);
  const n = Number(trimmed);
  if (n < min || (max !== undefined && n > max)) {
    throw new ConfigError(max !== undefined
      ? `${name} must be between ${min} and ${max}, got ${n}`
      : `${name} must be ${min} or more, got ${n}`);
  }
  return n;
}

/** Validate an enum option value. */
export function parseEnumOption<T extends string>(name: string, value: string, values: readonly T[]): T {
  if (!(values as readonly string[]).includes(value)) {
    throw new ConfigError(`${name} must be one of ${values.join(', ')}, got "${value}"`);
  }
  return value as T;
}
