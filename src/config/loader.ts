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
  extends?: string | string[];
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
  gitignore?: boolean;
}

/** Shareable configs available as `"extends": "contexthound:<name>"`. */
export const BUILTIN_CONFIGS: Record<string, RcFile> = {
  // Fail on high and critical findings; skip low-confidence rules.
  'contexthound:recommended': { failOn: 'high', minConfidence: 'medium' },
  // Fail on medium and above, and on any single file scoring 60 or more.
  'contexthound:strict': { failOn: 'medium', failFileThreshold: 60 },
};

/** Config files looked for in the scan directory, in order. */
const IMPLICIT_CONFIG_FILES = ['.contexthoundrc.json', '.contexthoundrc', 'package.json'];

const MAX_EXTENDS_DEPTH = 10;

function parseJsonFile(file: string): unknown {
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new ConfigError(`could not read ${file}: ${(err as Error).message}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`could not parse ${file}: ${(err as Error).message}`);
  }
}

function validated(raw: unknown, source: string): RcFile {
  const problems = validateConfigObject(raw);
  if (problems.length > 0) {
    throw new ConfigError(`invalid config in ${source}:\n${problems.map(p => `  - ${p}`).join('\n')}`);
  }
  return raw as RcFile;
}

/**
 * Where an `extends` entry points. Only JSON is ever loaded: a config that
 * could run code would execute attacker-controlled files when scanning an
 * untrusted pull request.
 */
function resolveExtends(spec: string, fromDir: string, source: string): { file?: string; builtin?: RcFile } {
  if (spec.startsWith('contexthound:')) {
    const builtin = BUILTIN_CONFIGS[spec];
    if (!builtin) {
      throw new ConfigError(`unknown shared config "${spec}" in ${source}; available: ${Object.keys(BUILTIN_CONFIGS).join(', ')}`);
    }
    return { builtin };
  }
  let file: string;
  if (spec.startsWith('.') || path.isAbsolute(spec)) {
    file = path.resolve(fromDir, spec);
  } else {
    try {
      file = require.resolve(spec, { paths: [fromDir] });
    } catch {
      throw new ConfigError(`cannot find "${spec}" (extended from ${source})`);
    }
  }
  if (path.extname(file).toLowerCase() !== '.json') {
    throw new ConfigError(`"${spec}" in ${source} must be a .json file; configs that run code are not supported`);
  }
  if (!fs.existsSync(file)) throw new ConfigError(`config file not found: ${file} (extended from ${source})`);
  return { file };
}

/** Merge a config with everything it extends. Later entries win; arrays are replaced, not merged. */
function withExtends(rc: RcFile, fromDir: string, source: string, chain: string[]): RcFile {
  if (rc.extends === undefined) return rc;
  if (chain.length > MAX_EXTENDS_DEPTH) throw new ConfigError(`"extends" is nested more than ${MAX_EXTENDS_DEPTH} levels deep in ${source}`);
  const specs = Array.isArray(rc.extends) ? rc.extends : [rc.extends];
  let merged: RcFile = {};
  for (const spec of specs) {
    const target = resolveExtends(spec, fromDir, source);
    let base: RcFile;
    if (target.builtin) {
      base = target.builtin;
    } else {
      const file = target.file as string;
      if (chain.includes(file)) throw new ConfigError(`circular "extends": ${[...chain, file].join(' -> ')}`);
      base = withExtends(validated(parseJsonFile(file), file), path.dirname(file), file, [...chain, file]);
    }
    merged = { ...merged, ...base };
  }
  const own: RcFile = { ...rc };
  delete own.extends;
  return { ...merged, ...own };
}

function readRcFile(resolvedPath: string, explicit: boolean): RcFile {
  if (!fs.existsSync(resolvedPath)) {
    // Only the implicit default location may be absent. A path the user named
    // (--config or HOUND_CONFIG) that does not exist is a mistake, and silently
    // falling back to defaults would drop their gates.
    if (explicit) throw new ConfigError(`config file not found: ${resolvedPath}`);
    return {};
  }

  let raw = parseJsonFile(resolvedPath);
  let source = resolvedPath;
  if (path.basename(resolvedPath) === 'package.json') {
    const section = (raw as Record<string, unknown> | null)?.contexthound;
    if (section === undefined) {
      if (explicit) throw new ConfigError(`${resolvedPath} has no "contexthound" section`);
      return {};
    }
    raw = section;
    source = `${resolvedPath} ("contexthound")`;
  }
  const rc = validated(raw, source);
  return withExtends(rc, path.dirname(resolvedPath), source, [resolvedPath]);
}

/** The config file to use when none is named: the first that exists and applies. */
function findImplicitConfig(cwd: string): string | null {
  for (const name of IMPLICIT_CONFIG_FILES) {
    const file = path.join(cwd, name);
    if (!fs.existsSync(file)) continue;
    if (name === 'package.json') {
      try {
        const pkg = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>;
        if (pkg && typeof pkg === 'object' && 'contexthound' in pkg) return file;
      } catch {
        // An unparsable package.json is not ours to report.
      }
      continue;
    }
    return file;
  }
  return null;
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
      : findImplicitConfig(cwd);

  const rc = resolvedConfigPath ? readRcFile(resolvedConfigPath, explicit) : {};

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
    gitignore: rc.gitignore,
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
