import type { ScanResult, Finding } from '../types.js';
import { VERSION } from '../version.js';
import { FINGERPRINT_VERSION } from '../scanner/fingerprint.js';

interface SarifLog {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[]; precision: string; 'problem.severity': string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: Record<string, string>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region: { startLine: number; endLine: number };
  };
}

function severityToLevel(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high': return 'error';
    case 'medium': return 'warning';
    default: return 'note';
  }
}

function confidenceToPrecision(confidence: string): string {
  switch (confidence) {
    case 'high': return 'high';
    case 'medium': return 'medium';
    default: return 'low';
  }
}

export function buildSarifReport(result: ScanResult): string {
  const ruleIds = new Set(result.allFindings.map(f => f.id));

  // Build unique rules from findings
  const rulesMap = new Map<string, SarifRule>();
  for (const finding of result.allFindings) {
    if (!rulesMap.has(finding.id)) {
      const tags = ['security', 'prompt-injection'];
      if (finding.mitre) tags.push(`attack:${finding.mitre}`);
      rulesMap.set(finding.id, {
        id: finding.id,
        name: finding.id,
        shortDescription: { text: finding.title },
        fullDescription: { text: `${finding.title}. ${finding.remediation}` },
        ...(finding.mitre && { helpUri: `https://attack.mitre.org/techniques/${finding.mitre.replace('.', '/')}` }),
        properties: {
          tags,
          precision: confidenceToPrecision(finding.confidence),
          'problem.severity': finding.severity,
        },
      });
    }
  }

  const sarifResults: SarifResult[] = result.allFindings.map((f: Finding) => ({
    ruleId: f.id,
    level: severityToLevel(f.severity),
    message: { text: `${f.title}: ${f.evidence}` },
    locations: [{
      physicalLocation: {
        artifactLocation: {
          uri: f.file.replace(/\\/g, '/'),
          uriBaseId: '%SRCROOT%',
        },
        region: {
          startLine: f.lineStart,
          endLine: f.lineEnd,
        },
      },
    }],
    ...(f.fingerprint && { partialFingerprints: { [FINGERPRINT_VERSION]: f.fingerprint } }),
  }));

  const log: SarifLog = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ContextHound',
          version: VERSION,
          informationUri: 'https://github.com/IulianVOStrut/ContextHound',
          rules: Array.from(rulesMap.values()),
        },
      },
      results: sarifResults,
    }],
  };

  // Suppress unused variable warning
  void ruleIds;

  return JSON.stringify(log, null, 2);
}
