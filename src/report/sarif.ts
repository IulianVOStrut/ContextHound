import type { ScanResult, Finding, Severity, Confidence } from '../types.js';
import type { Rule } from '../rules/types.js';
import { allRules } from '../rules/index.js';
import { owaspLabel } from '../rules/owasp.js';
import { VERSION } from '../version.js';
import { FINGERPRINT_VERSION } from '../scanner/fingerprint.js';

const INFORMATION_URI = 'https://github.com/IulianVOStrut/ContextHound';

interface SarifLog {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  invocations: SarifInvocation[];
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  semanticVersion: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri?: string;
  defaultConfiguration: { level: string };
  properties: {
    tags: string[];
    precision: string;
    'problem.severity': string;
    'security-severity': string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  properties: { confidence: string; severity: string };
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region: { startLine: number; endLine: number };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  toolExecutionNotifications: {
    level: string;
    message: { text: string };
    locations?: { physicalLocation: { artifactLocation: { uri: string; uriBaseId: string } } }[];
  }[];
}

/** The metadata SARIF needs about a rule, from a Rule or a Finding. */
interface RuleInfo {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  remediation: string;
  category?: string;
  mitre?: string;
  owasp?: string[];
}

function severityToLevel(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high': return 'error';
    case 'medium': return 'warning';
    default: return 'note';
  }
}

/**
 * CVSS-style score GitHub code scanning uses to label alerts Critical (9.0+),
 * High (7.0-8.9), Medium (4.0-6.9) or Low.
 */
function securitySeverity(severity: string): string {
  switch (severity) {
    case 'critical': return '9.5';
    case 'high': return '8.0';
    case 'medium': return '5.5';
    default: return '3.0';
  }
}

function mitreUri(mitre: string): string {
  return `https://attack.mitre.org/techniques/${mitre.replace('.', '/')}`;
}

function toSarifRule(info: RuleInfo): SarifRule {
  const tags = ['security', 'prompt-injection'];
  if (info.category) tags.push(info.category);
  if (info.mitre) tags.push(`attack:${info.mitre}`);
  for (const id of info.owasp ?? []) tags.push(`owasp:${id}`);

  const markdown = [
    `**${info.id}: ${info.title}**`,
    '',
    `Severity: ${info.severity}. Confidence: ${info.confidence}.`,
    '',
    `**Remediation:** ${info.remediation}`,
    ...(info.mitre ? ['', `MITRE ATT&CK: [${info.mitre}](${mitreUri(info.mitre)})`] : []),
    ...(info.owasp?.length ? ['', `OWASP: ${info.owasp.map(owaspLabel).join(', ')}`] : []),
    '',
    `Run \`hound explain ${info.id}\` for details and the suppression comment.`,
  ].join('\n');

  return {
    id: info.id,
    name: info.id,
    shortDescription: { text: info.title },
    fullDescription: { text: `${info.title}. ${info.remediation}` },
    help: { text: `${info.title}. Remediation: ${info.remediation}`, markdown },
    ...(info.mitre && { helpUri: mitreUri(info.mitre) }),
    defaultConfiguration: { level: severityToLevel(info.severity) },
    properties: {
      tags,
      precision: info.confidence,
      'problem.severity': info.severity,
      'security-severity': securitySeverity(info.severity),
    },
  };
}

/**
 * Build a SARIF 2.1.0 log. `driver.rules` lists every rule in `rules` (all
 * built-in rules by default) so code scanning can show rule help for any
 * alert, plus any rule that only appears in findings, such as plugin rules.
 */
export function buildSarifReport(result: ScanResult, rules: readonly Rule[] = allRules): string {
  const descriptors: SarifRule[] = [];
  const indexById = new Map<string, number>();
  const add = (info: RuleInfo) => {
    if (indexById.has(info.id)) return;
    indexById.set(info.id, descriptors.length);
    descriptors.push(toSarifRule(info));
  };
  for (const rule of rules) add(rule);
  for (const finding of result.allFindings) add(finding);

  const results: SarifResult[] = result.allFindings.map((f: Finding) => ({
    ruleId: f.id,
    ruleIndex: indexById.get(f.id) as number,
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
    properties: { confidence: f.confidence, severity: f.severity },
  }));

  const notifications: SarifInvocation['toolExecutionNotifications'] = (result.skippedFiles ?? []).map(s => ({
    level: 'warning',
    message: { text: `Skipped ${s.file}: ${s.size} bytes is over the maxFileSize limit.` },
    locations: [{ physicalLocation: { artifactLocation: { uri: s.file.replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' } } }],
  }));
  if (result.suppressedCount) {
    notifications.push({
      level: 'note',
      message: { text: `${result.suppressedCount} finding(s) suppressed by inline hound-disable comments.` },
    });
  }

  const log: SarifLog = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ContextHound',
          version: VERSION,
          semanticVersion: VERSION,
          informationUri: INFORMATION_URI,
          rules: descriptors,
        },
      },
      invocations: [{ executionSuccessful: true, toolExecutionNotifications: notifications }],
      results,
    }],
  };

  return JSON.stringify(log, null, 2);
}
