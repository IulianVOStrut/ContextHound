export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type OutputFormat = 'console' | 'json' | 'sarif' | 'github-annotations' | 'markdown' | 'jsonl' | 'html' | 'csv' | 'junit';
export type FailOn = 'critical' | 'high' | 'medium';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  evidence: string;
  file: string;
  lineStart: number;
  lineEnd: number;
  remediation: string;
  riskPoints: number;
  mitre?: string;
  /** Stable identity used by baselines and SARIF partialFingerprints. */
  fingerprint?: string;
}

export interface FileResult {
  file: string;
  findings: Finding[];
  fileScore: number;
}

export interface ScanResult {
  repoScore: number;
  scoreLabel: 'low' | 'medium' | 'high' | 'critical';
  files: FileResult[];
  allFindings: Finding[];
  threshold: number;
  passed: boolean;
  fileThresholdBreached?: boolean;
  /** Number of findings silenced by inline suppression comments. */
  suppressedCount?: number;
  /** Suppression directives that never matched a finding (dead suppressions). */
  unusedSuppressions?: UnusedSuppression[];
  /** Why the scan failed its gates; absent when it passed. */
  failures?: ScanFailure[];
  /** Files not scanned because they exceed `maxFileSize`. */
  skippedFiles?: SkippedFile[];
}

export interface ScanFailure {
  /** threshold and file-threshold exit with 2, fail-on with 3. */
  kind: 'threshold' | 'file-threshold' | 'fail-on';
  message: string;
}

export interface SkippedFile {
  file: string;
  size: number;
  reason: 'max-file-size';
}

export interface UnusedSuppression {
  file: string;
  line: number;
  ruleIds: string[] | null;
  reason?: string;
}

export interface AuditConfig {
  include: string[];
  exclude: string[];
  threshold: number;
  formats: OutputFormat[];
  out?: string;
  maxFindings?: number;
  /** Files larger than this many bytes are skipped (and reported). 0 disables the limit. */
  maxFileSize?: number;
  failOn?: FailOn;
  verbose: boolean;
  excludeRules?: string[];
  includeRules?: string[];
  minConfidence?: Confidence;
  failFileThreshold?: number;
  concurrency?: number;
  cache?: boolean;
  baseline?: string;
  plugins?: string[];
  /** When true, scan only files changed vs. this git ref (PR-gate mode). */
  diff?: string;
  /** When true, report inline suppression directives that matched nothing. */
  reportUnusedSuppressions?: boolean;
}
