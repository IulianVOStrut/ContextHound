import fs from 'fs';
import path from 'path';
import type { AuditConfig, Confidence, FailOn } from '../types.js';
import { DEFAULT_CONFIG } from './defaults.js';

interface RcFile {
  include?: string[];
  exclude?: string[];
  threshold?: number;
  formats?: string[];
  out?: string;
  maxFindings?: number;
  maxFileSize?: number;
  failOn?: string;
  verbose?: boolean;
  excludeRules?: string[];
  includeRules?: string[];
  minConfidence?: string;
  failFileThreshold?: number;
  concurrency?: number;
  cache?: boolean;
  baseline?: string;
  plugins?: string[];
}

export function loadConfig(configPath?: string, cwd: string = process.cwd()): AuditConfig {
  // HOUND_CONFIG env var can specify an alternative config path
  const resolvedConfigPath = configPath
    ? path.resolve(configPath)
    : process.env.HOUND_CONFIG
      ? path.resolve(process.env.HOUND_CONFIG)
      : path.join(cwd, '.contexthoundrc.json');

  let rc: RcFile = {};
  if (fs.existsSync(resolvedConfigPath)) {
    try {
      rc = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8')) as RcFile;
    } catch {
      console.warn(`Warning: Could not parse config file at ${resolvedConfigPath}`);
    }
  }

  // Build base config from file
  const base: AuditConfig = {
    include: rc.include ?? DEFAULT_CONFIG.include,
    exclude: rc.exclude ?? DEFAULT_CONFIG.exclude,
    threshold: rc.threshold ?? DEFAULT_CONFIG.threshold,
    formats: (rc.formats as AuditConfig['formats']) ?? DEFAULT_CONFIG.formats,
    out: rc.out,
    maxFindings: rc.maxFindings,
    maxFileSize: rc.maxFileSize,
    failOn: rc.failOn as FailOn,
    verbose: rc.verbose ?? DEFAULT_CONFIG.verbose,
    excludeRules: rc.excludeRules,
    includeRules: rc.includeRules,
    minConfidence: rc.minConfidence as Confidence,
    failFileThreshold: rc.failFileThreshold,
    concurrency: rc.concurrency,
    cache: rc.cache,
    baseline: rc.baseline,
    plugins: rc.plugins,
  };

  // Apply environment variable overrides (priority: CLI > env > config > default)
  // These are applied here so CLI options (applied after this call) can still override.
  if (process.env.HOUND_THRESHOLD) {
    const parsed = parseInt(process.env.HOUND_THRESHOLD, 10);
    if (!isNaN(parsed)) base.threshold = parsed;
  }
  if (process.env.HOUND_FAIL_ON) {
    base.failOn = process.env.HOUND_FAIL_ON as FailOn;
  }
  if (process.env.HOUND_MIN_CONFIDENCE) {
    base.minConfidence = process.env.HOUND_MIN_CONFIDENCE as Confidence;
  }
  if (process.env.HOUND_VERBOSE) {
    const v = process.env.HOUND_VERBOSE.toLowerCase();
    base.verbose = v === '1' || v === 'true' || v === 'yes';
  }

  return base;
}
