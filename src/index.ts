// Library entry point: `require('context-hound')` / `import ... from 'context-hound'`.
// Importing this module has no side effects; the CLI lives in cli.ts (bin: hound).

export { VERSION } from './version.js';

// Scanning
export { runScan } from './scanner/pipeline.js';
export { extractPrompts } from './scanner/extractor.js';
export type { ExtractedPrompt } from './scanner/extractor.js';
export { applyBaseline, loadBaseline } from './scanner/baseline.js';
export type { BaselineOutcome } from './scanner/baseline.js';
export { analyzePrompt, buildScanResult, scoreFile, scoreRepo, combineRisk, scoreLabel } from './scoring/index.js';

// Configuration
export { loadConfig, ConfigError } from './config/loader.js';
export { DEFAULT_CONFIG, DEFAULT_INCLUDE_GLOBS, DEFAULT_EXCLUDE_GLOBS, DEFAULT_MAX_FILE_SIZE } from './config/defaults.js';
export { validateConfigObject, buildJsonSchema, OUTPUT_FORMATS } from './config/schema.js';
export { PRESETS, resolvePresets } from './config/presets.js';

// Rules
export { allRules, OWASP_CATEGORIES, owaspLabel } from './rules/index.js';
export type { Rule, RuleMatch } from './rules/index.js';

// Report formatters (pure: they return strings and write nothing)
export { buildJsonReport } from './report/json.js';
export { buildJsonlReport } from './report/jsonl.js';
export { buildSarifReport } from './report/sarif.js';
export { buildMarkdownReport } from './report/markdown.js';
export { buildHtmlReport } from './report/html.js';
export { buildCsvReport } from './report/csv.js';
export { buildJunitReport } from './report/junit.js';
export { buildGithubAnnotationsReport, buildStepSummary } from './report/githubAnnotations.js';
export { buildPrComment, PR_COMMENT_MARKER } from './report/prComment.js';
export type { PrCommentOptions } from './report/prComment.js';

export type {
  AuditConfig, Finding, FileResult, ScanResult, ScanFailure, SkippedFile, UnusedSuppression,
  Severity, Confidence, OutputFormat, FailOn,
} from './types.js';
