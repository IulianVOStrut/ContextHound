#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import { loadConfig, ConfigError, parseEnumOption, parseIntegerOption } from './config/loader.js';
import { OUTPUT_FORMATS, FAIL_ON_LEVELS, CONFIDENCE_LEVELS } from './config/schema.js';
import { runScan } from './scanner/pipeline.js';
import { discoverFiles } from './scanner/discover.js';
import { resolveDiffRef } from './scanner/gitDiff.js';
import { applyBaseline, loadBaseline } from './scanner/baseline.js';
import { createPathMapper, pathKey } from './scanner/paths.js';
import { PRESETS, resolvePresets } from './config/presets.js';
import { printConsoleReport } from './report/console.js';
import { buildJsonReport } from './report/json.js';
import { buildSarifReport } from './report/sarif.js';
import { buildGithubAnnotationsReport, buildStepSummary } from './report/githubAnnotations.js';
import { buildMarkdownReport } from './report/markdown.js';
import { buildHtmlReport } from './report/html.js';
import { buildJsonlReport } from './report/jsonl.js';
import { buildCsvReport } from './report/csv.js';
import { buildJunitReport } from './report/junit.js';
import { toTerminalSafe } from './report/sanitize.js';
import { allRules } from './rules/index.js';
import { VERSION } from './version.js';
import { DEFAULT_MAX_FILE_SIZE, DEFAULT_INCLUDE_GLOBS, DEFAULT_EXCLUDE_GLOBS } from './config/defaults.js';
import type { AuditConfig, OutputFormat, ScanResult } from './types.js';

const program = new Command();

program
  .name('hound')
  .description('ContextHound: Scan LLM prompts for injection and security risks')
  .version(VERSION);

// ── init command ─────────────────────────────────────────────────────────────

program
  .command('init')
  .description('Scaffold a .contexthoundrc.json config file')
  .option('--force', 'Overwrite existing config')
  .action((opts: { force?: boolean }) => {
    const outPath = path.join(process.cwd(), '.contexthoundrc.json');
    if (fs.existsSync(outPath) && !opts.force) {
      console.error('Error: .contexthoundrc.json already exists. Use --force to overwrite.');
      process.exit(1);
    }

    const template = {
      "$schema": "https://raw.githubusercontent.com/IulianVOStrut/ContextHound/main/schema/contexthoundrc.schema.json",
      "include": DEFAULT_INCLUDE_GLOBS,
      "exclude": DEFAULT_EXCLUDE_GLOBS,
      "threshold": 60,
      "formats": ["console"],
      "failOn": null,
      "maxFindings": null,
      "maxFileSize": 1048576,
      "verbose": false,
      "excludeRules": [],
      "includeRules": [],
      "minConfidence": null,
      "failFileThreshold": null,
      "concurrency": 8,
      "cache": true,
      "plugins": [],
    };

    fs.writeFileSync(outPath, JSON.stringify(template, null, 2), 'utf8');
    console.log('Created .contexthoundrc.json');
    console.log('');
    console.log('Next steps:');
    console.log('  1. Edit .contexthoundrc.json to match your project layout');
    console.log('  2. Run: hound scan --verbose');
    console.log('  3. Set threshold and failOn to fit your risk tolerance');
  });

// ── explain command ────────────────────────────────────────────────────────

const CATEGORY_BLURB: Record<string, string> = {
  'injection': 'Untrusted input reaching the model without isolation, letting an attacker steer the prompt.',
  'exfiltration': 'Sensitive data (secrets, history, system prompt) leaving the trust boundary.',
  'jailbreak': 'Attempts to override, dismiss, or void the system instructions and safety constraints.',
  'unsafe-tools': 'Model output driving privileged tools or actions without a human/guard in the loop.',
  'multimodal': 'Injection or data flow through image, audio, or OCR/vision inputs.',
  'skills': 'Risks in shareable skill/agent definitions (SKILL.md, marketplaces).',
  'agentic': 'Multi-step / multi-agent pipeline risks: unbounded loops, unsigned messages, error swallowing.',
  'mcp': 'Model Context Protocol risks: poisoned tool descriptions, confused-deputy token forwarding, transport.',
  'supply-chain': 'Malicious or safety-ablating dependencies entering the build.',
  'dos': 'Resource-exhaustion / cost-amplification against the model or pipeline.',
  'persistence': 'Footholds an attacker establishes after initial access (cron, services, profile, log tampering).',
};

function mitreUrl(mitre: string): string {
  return `https://attack.mitre.org/techniques/${mitre.replace('.', '/')}`;
}

program
  .command('explain <ruleId>')
  .description('Explain a rule (or a rule family by prefix, e.g. INJ)')
  .option('-f, --format <format>', 'Output format: console|json', 'console')
  .action((ruleId: string, opts: { format: string }) => {
    const q = ruleId.toUpperCase();
    const matches = allRules.filter(r => r.id.toUpperCase() === q || r.id.toUpperCase().startsWith(q));
    if (matches.length === 0) {
      console.error(`No rule matches "${ruleId}". Try 'hound scan --list-rules'.`);
      process.exit(1);
    }

    if (opts.format === 'json') {
      console.log(JSON.stringify(matches.map(r => ({
        id: r.id, title: r.title, severity: r.severity, confidence: r.confidence,
        category: r.category, mitre: r.mitre ?? null,
        mitreUrl: r.mitre ? mitreUrl(r.mitre) : null,
        categoryDescription: CATEGORY_BLURB[r.category] ?? null,
        remediation: r.remediation,
      })), null, 2));
      process.exit(0);
    }

    for (const r of matches) {
      console.log('');
      console.log(`${r.id} — ${r.title}`);
      console.log('─'.repeat(Math.max(20, r.id.length + r.title.length + 3)));
      console.log(`Severity:    ${r.severity}`);
      console.log(`Confidence:  ${r.confidence}`);
      console.log(`Category:    ${r.category}`);
      if (CATEGORY_BLURB[r.category]) console.log(`             ${CATEGORY_BLURB[r.category]}`);
      if (r.mitre) {
        console.log(`MITRE:       ${r.mitre}  (${mitreUrl(r.mitre)})`);
      }
      console.log(`Remediation: ${r.remediation}`);
      console.log(`Suppress:    // hound-disable-next-line ${r.id}`);
    }
    console.log('');
    if (matches.length > 1) console.log(`${matches.length} rules matched "${ruleId}".`);
    process.exit(0);
  });

// ── scan command ─────────────────────────────────────────────────────────────

program
  .command('scan', { isDefault: true })
  .description('Scan a repository for prompt-injection risks')
  .option('-c, --config <path>', 'Path to .contexthoundrc.json config file')
  .option('-f, --format <formats>', 'Output formats: console,json,sarif,github-annotations,markdown,jsonl,html,csv,junit (comma-separated; default: config file, else console)')
  .option('-o, --out <path>', 'Output path for json/sarif/markdown files')
  .option('-t, --threshold <n>', 'Risk score threshold (0-100). Fail if score >= threshold')
  .option('--fail-on <level>', 'Fail on first finding of this severity: critical|high|medium')
  .option('--max-findings <n>', 'Stop after N findings')
  .option('--fail-file-threshold <n>', 'Fail if any single file score >= N')
  .option('--max-file-size <bytes>', 'Skip files larger than this many bytes (default: 1048576, 0 = no limit)')
  .option('-v, --verbose', 'Verbose output (show remediation and confidence)')
  .option('--dir <path>', 'Directory to scan (default: current working directory)')
  .option('--list-rules', 'Print all rules and exit')
  .option('--watch', 'Re-scan on file changes')
  .option('--concurrency <n>', 'Max files scanned in parallel (default: 8)')
  .option('--no-cache', 'Disable incremental file cache')
  .option('--no-gitignore', 'Also scan files that git ignores')
  .option('--baseline <path>', 'Compare against a saved JSON report; only report new findings')
  .option('--min-confidence <level>', 'Minimum confidence level to report: low|medium|high (default: low)')
  .option('--diff [ref]', 'Scan only files changed vs. a git ref (default: origin/main)')
  .option('--report-unused-suppressions', 'List inline suppression comments that matched no finding')
  .option('--preset <names>', 'Enable a curated rule bundle (comma-separated): ' + Object.keys(PRESETS).join(', '))
  .option('--list-presets', 'Print available rule presets and exit')
  .action(async (opts: {
    config?: string;
    format?: string;
    out?: string;
    threshold?: string;
    failOn?: string;
    maxFindings?: string;
    maxFileSize?: string;
    failFileThreshold?: string;
    verbose?: boolean;
    dir?: string;
    listRules?: boolean;
    watch?: boolean;
    concurrency?: string;
    cache?: boolean;
    gitignore?: boolean;
    baseline?: string;
    minConfidence?: string;
    diff?: string | boolean;
    reportUnusedSuppressions?: boolean;
    preset?: string;
    listPresets?: boolean;
  }) => {
    // ── --list-presets ────────────────────────────────────────────────────
    if (opts.listPresets) {
      for (const [name, preset] of Object.entries(PRESETS)) {
        console.log(`${name.padEnd(18)} ${preset.description}`);
        console.log(`${' '.repeat(18)} rules: ${preset.rules.join(', ')}`);
      }
      process.exit(0);
    }
    // ── --list-rules ──────────────────────────────────────────────────────
    if (opts.listRules) {
      const formats = (opts.format ?? '').split(',').map(f => f.trim());
      if (formats.includes('json')) {
        console.log(JSON.stringify(allRules.map(r => ({
          id: r.id, severity: r.severity, confidence: r.confidence,
          category: r.category, title: r.title,
        })), null, 2));
      } else {
        const header = 'ID        SEV       CONF    CATEGORY          TITLE';
        console.log(header);
        console.log('-'.repeat(header.length));
        for (const r of allRules) {
          const id = r.id.padEnd(10);
          const sev = r.severity.padEnd(10);
          const conf = r.confidence.padEnd(8);
          const cat = r.category.padEnd(18);
          console.log(`${id}${sev}${conf}${cat}${r.title}`);
        }
        console.log('');
        console.log(`Total: ${allRules.length} rules`);
      }
      process.exit(0);
    }

    const cwd = opts.dir ? path.resolve(opts.dir) : process.cwd();

    let config: AuditConfig;
    try {
      config = buildConfig(opts, cwd);
    } catch (err) {
      if (err instanceof ConfigError) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }
    const formats = config.formats;
    // Human-readable status lines go to stderr whenever stdout carries a
    // machine-readable stream, so `--format jsonl | jq` sees only JSON.
    const machineStdout = formats.includes('jsonl') && !config.out;
    const status = machineStdout ? console.error : console.log;

    // Never scan our own report files: they quote evidence and would be
    // re-reported on every run.
    if (config.out) {
      const rel = path.relative(cwd, path.resolve(cwd, config.out)).split(path.sep).join('/');
      if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
        config.exclude = [...config.exclude, rel, `${rel}.*`];
      }
    }

    // --preset adds curated rule-ID patterns to includeRules (union with any
    // patterns already set via config or --include-rules).
    if (opts.preset) {
      try {
        const presetRules = resolvePresets(opts.preset);
        config.includeRules = [...new Set([...(config.includeRules ?? []), ...presetRules])];
      } catch (err) {
        console.error((err as Error).message);
        process.exit(1);
      }
    }

    if (config.verbose) {
      status(`Scanning: ${cwd}`);
      status(`Threshold: ${config.threshold}`);
      status(`Formats: ${config.formats.join(', ')}`);
      if (config.cache !== false) status('Cache: enabled (.hound-cache.json)');
      if (config.plugins?.length) status(`Plugins: ${config.plugins.join(', ')}`);
      if (config.baseline) status(`Baseline: ${config.baseline}`);
      if (config.diff) status(`Diff: changed files vs. ${config.diff}`);
    }

    // ── --watch mode ──────────────────────────────────────────────────────
    if (opts.watch) {
      await runWatchMode(cwd, config, status);
      return;
    }

    // ── Single scan ───────────────────────────────────────────────────────
    let result: ScanResult;
    try {
      result = await scanWithBaseline(cwd, config, status);
    } catch (err) {
      console.error('Error during scan:', err);
      process.exit(1);
    }

    emitReports(result, config, cwd, status);

    // Exit codes: 0 passed, 1 error or bad arguments, 2 threshold or file
    // threshold breached, 3 fail-on violation (takes precedence).
    if (!result.passed) {
      process.exit(result.failures?.some(f => f.kind === 'fail-on') ? 3 : 2);
    }
    process.exit(0);
  });

// ── scanning and report output ────────────────────────────────────────────────

type StatusLogger = (message: string) => void;

async function scanWithBaseline(cwd: string, config: AuditConfig, status: StatusLogger): Promise<ScanResult> {
  const result = await runScan(cwd, config);
  if (!config.baseline) return result;
  const baselineFindings = loadBaseline(config.baseline);
  if (baselineFindings === null) {
    console.warn(`Warning: could not load baseline from ${config.baseline}; reporting all findings`);
    return result;
  }
  const outcome = applyBaseline(result, baselineFindings, config, createPathMapper(cwd).toReport);
  status(`Baseline: ${outcome.known} known · ${outcome.added} new · ${outcome.resolved} resolved`);
  return outcome.result;
}

/** Absolute paths of every report file the current config writes. */
function reportPaths(config: AuditConfig, cwd: string): Partial<Record<OutputFormat, string>> {
  const withExt = (ext: string, fallback: string) =>
    config.out ? path.resolve(cwd, config.out.endsWith(ext) ? config.out : `${config.out}${ext}`) : path.join(cwd, fallback);
  return {
    json: config.out ? path.resolve(cwd, `${config.out}.json`) : path.join(cwd, 'hound-results.json'),
    sarif: withExt('.sarif', 'results.sarif'),
    markdown: withExt('.md', 'hound-report.md'),
    html: withExt('.html', 'hound-report.html'),
    csv: withExt('.csv', 'hound-report.csv'),
    junit: withExt('.xml', 'hound-report.xml'),
    ...(config.out && { jsonl: withExt('.jsonl', 'hound-results.jsonl') }),
  };
}

const FILE_BUILDERS: Partial<Record<OutputFormat, [string, (r: ScanResult) => string]>> = {
  json: ['JSON', buildJsonReport],
  sarif: ['SARIF', buildSarifReport],
  markdown: ['Markdown', buildMarkdownReport],
  html: ['HTML', buildHtmlReport],
  csv: ['CSV', buildCsvReport],
  junit: ['JUnit XML', buildJunitReport],
  jsonl: ['JSONL', buildJsonlReport],
};

function emitReports(result: ScanResult, config: AuditConfig, cwd: string, status: StatusLogger): void {
  const formats = config.formats;

  if (formats.includes('console')) printConsoleReport(result, config.verbose);

  // Oversized files are reported on stderr so machine-readable stdout stays clean,
  // and so padding a file past the limit cannot silently hide it.
  if (result.skippedFiles?.length) {
    const limit = config.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
    console.warn(`Skipped ${result.skippedFiles.length} file(s) larger than ${limit} bytes (raise with --max-file-size):`);
    for (const s of result.skippedFiles) console.warn(`  ${toTerminalSafe(s.file)} (${s.size} bytes)`);
  }

  if (result.suppressedCount) {
    status(`Suppressed: ${result.suppressedCount} finding(s) via inline hound-disable comments`);
  }
  if (config.reportUnusedSuppressions && result.unusedSuppressions?.length) {
    status(`\nUnused suppressions (${result.unusedSuppressions.length}), matched no finding:`);
    for (const u of result.unusedSuppressions) {
      const scope = u.ruleIds ? u.ruleIds.join(',') : 'all rules';
      status(`  ${toTerminalSafe(u.file)}:${u.line}  [${scope}]${u.reason ? `  (${toTerminalSafe(u.reason)})` : ''}`);
    }
  }

  const paths = reportPaths(config, cwd);
  for (const format of formats) {
    const builder = FILE_BUILDERS[format];
    const outPath = paths[format];
    if (!builder || !outPath) continue;
    fs.writeFileSync(outPath, builder[1](result), 'utf8');
    status(`${builder[0]} report written to: ${outPath}`);
  }

  // Formats written to stdout. JSONL is built from the final result, so
  // findings already in a baseline are not streamed.
  if (formats.includes('jsonl') && !config.out && result.allFindings.length > 0) {
    console.log(buildJsonlReport(result));
  }
  if (formats.includes('github-annotations')) {
    const annotations = buildGithubAnnotationsReport(result);
    if (annotations) console.log(annotations);
  }

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    if (formats.includes('github-annotations')) fs.appendFileSync(summaryPath, `\n${buildStepSummary(result)}\n`, 'utf8');
    if (formats.includes('markdown')) fs.appendFileSync(summaryPath, `\n${buildMarkdownReport(result)}\n`, 'utf8');
  }
}

// ── watch mode implementation ─────────────────────────────────────────────────

// Directories never worth watching; include/exclude decide the rest.
const WATCH_IGNORED_DIRS = /(^|[\\/])(node_modules|\.git|\.venv|venv|__pycache__)([\\/]|$)/;

async function runWatchMode(cwd: string, config: AuditConfig, status: StatusLogger): Promise<void> {
  const chokidar = await import('chokidar');
  const paths = createPathMapper(cwd);

  // Our own writes (cache and reports) must not trigger another rescan.
  const ownOutputs = new Set<string>([
    path.join(cwd, '.hound-cache.json'),
    ...Object.values(reportPaths(config, cwd)).filter((p): p is string => !!p),
  ].map(pathKey));

  const findingKeys = (r: ScanResult) =>
    new Map(r.files.map(fr => [fr.file, new Set(fr.findings.map(f => f.fingerprint ?? `${f.id}:${f.lineStart}`))]));

  let result = await scanWithBaseline(cwd, config, status);
  emitReports(result, config, cwd, status);
  let previous = findingKeys(result);

  const banner = () => status('\n[watching for changes, Ctrl+C to exit]\n');

  const pending = new Set<string>();
  let timer: NodeJS.Timeout | undefined;
  let running = Promise.resolve();

  const flush = async () => {
    const changed = [...pending];
    pending.clear();
    // Only rescan for files in scope (or previously reported, which covers deletions).
    const inScope = new Set((await discoverFiles(cwd, config)).map(pathKey));
    const relevant = changed.filter(p => inScope.has(pathKey(p)) || previous.has(paths.toReport(p)));
    if (relevant.length === 0) return;

    try {
      result = await scanWithBaseline(cwd, config, status);
      emitReports(result, config, cwd, status);
      const current = findingKeys(result);
      for (const abs of relevant) {
        const rel = paths.toReport(abs);
        const before = previous.get(rel) ?? new Set<string>();
        const after = current.get(rel) ?? new Set<string>();
        const added = [...after].filter(k => !before.has(k)).length;
        const resolved = [...before].filter(k => !after.has(k)).length;
        status(`[changed] ${toTerminalSafe(rel)}: +${added} new, -${resolved} resolved`);
      }
      previous = current;
    } catch (err) {
      console.error('Error during re-scan:', err);
    }
    banner();
  };

  const onEvent = (filePath: string) => {
    const abs = path.resolve(cwd, filePath);
    if (ownOutputs.has(pathKey(abs))) return;
    pending.add(abs);
    clearTimeout(timer);
    timer = setTimeout(() => { running = running.then(flush); }, 150);
  };

  // chokidar 4+ does not expand globs, so watch the directory and filter
  // events through the same include/exclude discovery the scanner uses.
  const watcher = chokidar.watch(cwd, {
    ignoreInitial: true,
    persistent: true,
    ignored: (p: string) => WATCH_IGNORED_DIRS.test(path.relative(cwd, p)),
  });
  watcher.on('add', onEvent);
  watcher.on('change', onEvent);
  watcher.on('unlink', onEvent);
  // Announce only once the initial crawl is done; before that, changes can be missed.
  await new Promise<void>(resolve => watcher.once('ready', () => resolve()));
  banner();

  process.on('SIGINT', async () => {
    await watcher.close();
    process.exit(0);
  });
}

// ── config assembly ───────────────────────────────────────────────────────────

interface ScanOptions {
  config?: string;
  format?: string;
  out?: string;
  threshold?: string;
  failOn?: string;
  maxFindings?: string;
  maxFileSize?: string;
  failFileThreshold?: string;
  verbose?: boolean;
  concurrency?: string;
  cache?: boolean;
  gitignore?: boolean;
  baseline?: string;
  minConfidence?: string;
  diff?: string | boolean;
  reportUnusedSuppressions?: boolean;
}

/** Merge config file, env vars and CLI flags (CLI wins), validating every flag. */
function buildConfig(opts: ScanOptions, cwd: string): AuditConfig {
  const fileConfig = loadConfig(opts.config, cwd);

  let formats = fileConfig.formats;
  if (opts.format !== undefined) {
    formats = opts.format.split(',').map(f => f.trim()).filter(Boolean)
      .map(f => parseEnumOption('--format', f, OUTPUT_FORMATS));
    if (formats.length === 0) throw new ConfigError('--format needs at least one format');
  }

  const int = (flag: string, value: string | undefined, min: number, max?: number) =>
    value === undefined ? undefined : parseIntegerOption(flag, value, min, max);

  return {
    ...fileConfig,
    formats,
    threshold: int('--threshold', opts.threshold, 0, 100) ?? fileConfig.threshold,
    out: opts.out ?? fileConfig.out,
    failOn: opts.failOn !== undefined ? parseEnumOption('--fail-on', opts.failOn, FAIL_ON_LEVELS) : fileConfig.failOn,
    maxFindings: int('--max-findings', opts.maxFindings, 1) ?? fileConfig.maxFindings,
    maxFileSize: int('--max-file-size', opts.maxFileSize, 0) ?? fileConfig.maxFileSize,
    failFileThreshold: int('--fail-file-threshold', opts.failFileThreshold, 0) ?? fileConfig.failFileThreshold,
    verbose: opts.verbose ?? fileConfig.verbose,
    concurrency: int('--concurrency', opts.concurrency, 1, 256) ?? fileConfig.concurrency,
    // commander defaults --no-cache options to true, so only an explicit
    // --no-cache (false) may override the config file.
    cache: opts.cache === false ? false : fileConfig.cache,
    gitignore: opts.gitignore === false ? false : fileConfig.gitignore,
    baseline: opts.baseline ?? fileConfig.baseline,
    minConfidence: opts.minConfidence !== undefined
      ? parseEnumOption('--min-confidence', opts.minConfidence, CONFIDENCE_LEVELS)
      : fileConfig.minConfidence,
    reportUnusedSuppressions: opts.reportUnusedSuppressions ?? fileConfig.reportUnusedSuppressions,
    diff: resolveDiffRef(opts.diff) ?? fileConfig.diff,
  };
}

program.parse(process.argv);
