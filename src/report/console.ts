import type { ScanResult, Finding, Severity } from '../types.js';
import { toTerminalSafe } from './sanitize.js';

// ANSI color codes (no external dependency needed for basic colors)
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const DIM = '\x1b[2m';

function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return `${BOLD}${RED}`;
    case 'high': return RED;
    case 'medium': return YELLOW;
    case 'low': return CYAN;
  }
}

function scoreColor(label: string): string {
  switch (label) {
    case 'critical': return `${BOLD}${RED}`;
    case 'high': return RED;
    case 'medium': return YELLOW;
    case 'low': return GREEN;
    default: return RESET;
  }
}

function printFinding(f: Finding, verbose: boolean): void {
  const color = severityColor(f.severity);
  console.log(`  ${color}[${f.severity.toUpperCase()}]${RESET} ${BOLD}${f.id}${RESET}: ${f.title}`);
  console.log(`    ${DIM}File:${RESET} ${toTerminalSafe(f.file)}:${f.lineStart}`);
  console.log(`    ${DIM}Evidence:${RESET} ${CYAN}${toTerminalSafe(f.evidence)}${RESET}`);
  if (verbose) {
    console.log(`    ${DIM}Confidence:${RESET} ${f.confidence}`);
    if (f.mitre) console.log(`    ${DIM}MITRE:${RESET}      ${CYAN}${f.mitre}${RESET}`);
    console.log(`    ${DIM}Risk points:${RESET} ${f.riskPoints}`);
    console.log(`    ${DIM}Remediation:${RESET} ${f.remediation}`);
  }
  console.log();
}

export function printConsoleReport(result: ScanResult, verbose: boolean = false): void {
  console.log();
  console.log(`${BOLD}${MAGENTA}=== ContextHound Scan ===${RESET}`);
  console.log();

  if (result.allFindings.length === 0) {
    console.log(`${GREEN}${BOLD}No findings. All clear.${RESET}`);
  } else {
    // Group by file
    for (const fileResult of result.files) {
      if (fileResult.findings.length === 0) continue;
      console.log(`${BOLD}${toTerminalSafe(fileResult.file)}${RESET} ${DIM}(file score: ${fileResult.fileScore})${RESET}`);
      for (const f of fileResult.findings) {
        printFinding(f, verbose);
      }
    }
  }

  const scoreCol = scoreColor(result.scoreLabel);
  console.log('─'.repeat(60));
  console.log(`${BOLD}Repo Risk Score:${RESET} ${scoreCol}${result.repoScore}/100 (${result.scoreLabel.toUpperCase()})${RESET}`);
  console.log(`${BOLD}Threshold:${RESET} ${result.threshold}`);
  console.log(`${BOLD}Total findings:${RESET} ${result.allFindings.length}`);
  const bySeverity = (['critical', 'high', 'medium', 'low'] as Severity[]).map(s => {
    const count = result.allFindings.filter(f => f.severity === s).length;
    return count > 0 ? `${severityColor(s)}${s}: ${count}${RESET}` : null;
  }).filter(Boolean).join('  ');
  if (bySeverity) console.log(`${BOLD}By severity:${RESET} ${bySeverity}`);
  console.log();

  if (result.passed) {
    console.log(`${GREEN}${BOLD}✓ PASSED${RESET} — score below threshold.`);
  } else {
    console.log(`${RED}${BOLD}✗ FAILED${RESET} — score meets or exceeds threshold.`);
  }
  console.log();
}
