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
}

export interface AuditConfig {
  include: string[];
  exclude: string[];
  threshold: number;
  formats: OutputFormat[];
  out?: string;
  maxFindings?: number;
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
}
