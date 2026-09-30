// Config file specification. The validator and the published JSON Schema
// (schema/contexthoundrc.schema.json) are both generated from CONFIG_FIELDS,
// so they cannot drift apart.

export const OUTPUT_FORMATS = [
  'console', 'json', 'sarif', 'github-annotations', 'markdown', 'jsonl', 'html', 'csv', 'junit',
] as const;
export const FAIL_ON_LEVELS = ['critical', 'high', 'medium'] as const;
export const CONFIDENCE_LEVELS = ['low', 'medium', 'high'] as const;

export type FieldSpec =
  | { kind: 'string'; description: string }
  | { kind: 'boolean'; description: string }
  | { kind: 'integer'; min: number; max?: number; nullable?: boolean; description: string }
  | { kind: 'enum'; values: readonly string[]; nullable?: boolean; description: string }
  | { kind: 'string[]'; description: string }
  | { kind: 'enum[]'; values: readonly string[]; description: string }
  | { kind: 'string|true'; description: string }
  | { kind: 'string|string[]'; description: string };

export const CONFIG_FIELDS: Record<string, FieldSpec> = {
  extends: { kind: 'string|string[]', description: 'Config(s) to build on: "contexthound:recommended", "contexthound:strict", a relative path to a .json file, or a package .json file. Later entries and this file override earlier ones.' },
  include: { kind: 'string[]', description: 'Glob patterns of files to scan.' },
  exclude: { kind: 'string[]', description: 'Glob patterns of files to skip.' },
  threshold: { kind: 'integer', min: 0, max: 100, description: 'Fail (exit 2) when the repo risk score is at or above this value.' },
  formats: { kind: 'enum[]', values: OUTPUT_FORMATS, description: 'Output formats.' },
  out: { kind: 'string', description: 'Base path for report files.' },
  maxFindings: { kind: 'integer', min: 1, nullable: true, description: 'Stop after this many findings.' },
  maxFileSize: { kind: 'integer', min: 0, description: 'Skip files larger than this many bytes. 0 disables the limit.' },
  failOn: { kind: 'enum', values: FAIL_ON_LEVELS, nullable: true, description: 'Fail (exit 3) on any finding of this severity or above.' },
  verbose: { kind: 'boolean', description: 'Show remediation, confidence and MITRE IDs.' },
  excludeRules: { kind: 'string[]', description: 'Rule IDs or prefix globs (e.g. "CMD-*") to skip.' },
  includeRules: { kind: 'string[]', description: 'Run only these rule IDs or prefix globs. Empty runs all rules.' },
  minConfidence: { kind: 'enum', values: CONFIDENCE_LEVELS, nullable: true, description: 'Skip rules below this confidence.' },
  failFileThreshold: { kind: 'integer', min: 0, nullable: true, description: 'Fail (exit 2) when any single file scores at or above this value.' },
  concurrency: { kind: 'integer', min: 1, max: 256, description: 'Maximum files processed in parallel.' },
  cache: { kind: 'boolean', description: 'Use the incremental scan cache (.hound-cache.json).' },
  baseline: { kind: 'string', description: 'Path to a previous JSON report; only new findings are reported.' },
  plugins: { kind: 'string[]', description: 'Paths to local .js files exporting a Rule or Rule[].' },
  diff: { kind: 'string|true', description: 'Scan only files changed vs. this git ref (true means origin/main).' },
  reportUnusedSuppressions: { kind: 'boolean', description: 'List inline suppression comments that matched no finding.' },
  gitignore: { kind: 'boolean', description: 'Skip files ignored by git (.gitignore, .git/info/exclude). Default true.' },
};

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  return typeof value === 'string' ? `"${value}"` : `${typeof value} ${JSON.stringify(value)}`;
}

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

function suggest(key: string): string {
  const lower = key.toLowerCase();
  let best: string | null = null;
  let bestDist = Infinity;
  for (const k of Object.keys(CONFIG_FIELDS)) {
    const d = levenshtein(lower, k.toLowerCase());
    if (d < bestDist) { best = k; bestDist = d; }
  }
  return best && bestDist <= 3 ? ` Did you mean "${best}"?` : '';
}

/** Check one value against its spec. Returns a problem description or null. */
export function checkField(spec: FieldSpec, value: unknown): string | null {
  if (value === null && 'nullable' in spec && spec.nullable) return null;
  switch (spec.kind) {
    case 'string':
      return typeof value === 'string' ? null : `must be a string, got ${describe(value)}`;
    case 'boolean':
      return typeof value === 'boolean' ? null : `must be true or false, got ${describe(value)}`;
    case 'integer': {
      if (typeof value !== 'number' || !Number.isInteger(value)) return `must be a whole number, got ${describe(value)}`;
      if (value < spec.min || (spec.max !== undefined && value > spec.max)) {
        return spec.max !== undefined
          ? `must be between ${spec.min} and ${spec.max}, got ${value}`
          : `must be ${spec.min} or more, got ${value}`;
      }
      return null;
    }
    case 'enum':
      return typeof value === 'string' && spec.values.includes(value)
        ? null
        : `must be one of ${spec.values.join(', ')}, got ${describe(value)}`;
    case 'string[]':
      return Array.isArray(value) && value.every(v => typeof v === 'string')
        ? null
        : `must be an array of strings, got ${describe(value)}`;
    case 'enum[]': {
      if (!Array.isArray(value)) return `must be an array, got ${describe(value)}`;
      const bad = value.filter(v => typeof v !== 'string' || !spec.values.includes(v));
      return bad.length === 0 ? null : `has unknown value(s) ${bad.map(describe).join(', ')}; allowed: ${spec.values.join(', ')}`;
    }
    case 'string|true':
      return typeof value === 'string' || value === true ? null : `must be a git ref string or true, got ${describe(value)}`;
    case 'string|string[]':
      return typeof value === 'string' || (Array.isArray(value) && value.every(v => typeof v === 'string'))
        ? null
        : `must be a string or an array of strings, got ${describe(value)}`;
  }
}

/**
 * Validate a parsed config file. Keys starting with "$" or "_" are reserved
 * for "$schema" and comments. Returns a list of human-readable problems.
 */
export function validateConfigObject(raw: unknown): string[] {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return ['the config file must contain a JSON object'];
  }
  const problems: string[] = [];
  for (const [key, value] of Object.entries(raw)) {
    if (key.startsWith('$') || key.startsWith('_')) continue;
    const spec = CONFIG_FIELDS[key];
    if (!spec) {
      problems.push(`unknown option "${key}".${suggest(key)}`);
      continue;
    }
    const problem = checkField(spec, value);
    if (problem) problems.push(`"${key}" ${problem}`);
  }
  return problems;
}

/** JSON Schema (draft-07) for .contexthoundrc.json, generated from CONFIG_FIELDS. */
export function buildJsonSchema(): Record<string, unknown> {
  const properties: Record<string, unknown> = {
    $schema: { type: 'string', description: 'URL or path of this JSON Schema.' },
  };
  for (const [key, spec] of Object.entries(CONFIG_FIELDS)) {
    const base = { description: spec.description };
    const nullable = 'nullable' in spec && spec.nullable;
    switch (spec.kind) {
      case 'string': properties[key] = { ...base, type: 'string' }; break;
      case 'boolean': properties[key] = { ...base, type: 'boolean' }; break;
      case 'integer':
        properties[key] = {
          ...base, type: nullable ? ['integer', 'null'] : 'integer', minimum: spec.min,
          ...(spec.max !== undefined && { maximum: spec.max }),
        };
        break;
      case 'enum':
        properties[key] = { ...base, enum: nullable ? [...spec.values, null] : [...spec.values] };
        break;
      case 'string[]': properties[key] = { ...base, type: 'array', items: { type: 'string' } }; break;
      case 'enum[]': properties[key] = { ...base, type: 'array', items: { enum: [...spec.values] } }; break;
      case 'string|true': properties[key] = { ...base, oneOf: [{ type: 'string' }, { const: true }] }; break;
      case 'string|string[]': properties[key] = { ...base, oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] }; break;
    }
  }
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'https://raw.githubusercontent.com/IulianVOStrut/ContextHound/main/schema/contexthoundrc.schema.json',
    title: 'ContextHound configuration',
    type: 'object',
    properties,
    patternProperties: { '^_': {} },
    additionalProperties: false,
  };
}
