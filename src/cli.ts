#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import { loadConfig } from './config/loader.js';
import { runScan } from './scanner/pipeline.js';
import { printConsoleReport } from './report/console.js';
import { buildJsonReport } from './report/json.js';
import { buildSarifReport } from './report/sarif.js';
import { buildGithubAnnotationsReport } from './report/githubAnnotations.js';
import { buildMarkdownReport } from './report/markdown.js';
import { buildJsonlReport } from './report/jsonl.js';
import { buildHtmlReport } from './report/html.js';
import { buildCsvReport } from './report/csv.js';
import { buildJunitReport } from './report/junit.js';
import { allRules } from './rules/index.js';
import type { AuditConfig, OutputFormat, FailOn, Finding, ScanResult } from './types.js';

const program = new Command();

program
  .name('hound')
  .description('ContextHound: Scan LLM prompts for injection and security risks')
  .version('1.6.0');

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
      "_comment": "ContextHound configuration — https://github.com/IulianVOStrut/ContextHound",
      "include": [
        "**/*.prompt", "**/*.prompt.*", "**/*.md", "**/*.txt",
        "**/*.yaml", "**/*.yml", "**/*.json",
        "**/*.ts", "**/*.js", "**/*.py", "**/*.go",
        "**/*.rs", "**/*.java", "**/*.kt", "**/*.cs",
        "**/*.php", "**/*.rb", "**/*.swift", "**/*.vue",
        "**/*.sh", "**/*.bash", "**/*.hs",
      ],
      "exclude": [
        "**/node_modules/**", "**/dist/**", "**/build/**",
        "**/.git/**", "**/coverage/**",
        "**/*.min.js", "**/*.lock",
        "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
        "**/src/rules/**",
      ],
      "threshold": 60,
      "formats": ["console"],
      "failOn": null,
      "maxFindings": null,
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

// ── scan command ─────────────────────────────────────────────────────────────

program
  .command('scan', { isDefault: true })
  .description('Scan a repository for prompt-injection risks')
  .option('-c, --config <path>', 'Path to .contexthoundrc.json config file')
  .option('-f, --format <formats>', 'Output formats: console,json,sarif,github-annotations,markdown,jsonl,html,csv,junit (comma-separated)', 'console')
  .option('-o, --out <path>', 'Output path for json/sarif/markdown files')
  .option('-t, --threshold <n>', 'Risk score threshold (0-100). Fail if score >= threshold')
  .option('--fail-on <level>', 'Fail on first finding of this severity: critical|high|medium')
  .option('--max-findings <n>', 'Stop after N findings')
  .option('--fail-file-threshold <n>', 'Fail if any single file score >= N')
  .option('-v, --verbose', 'Verbose output (show remediation and confidence)')
  .option('--dir <path>', 'Directory to scan (default: current working directory)')
  .option('--list-rules', 'Print all rules and exit')
  .option('--watch', 'Re-scan on file changes')
  .option('--concurrency <n>', 'Max files scanned in parallel (default: 8)')
  .option('--no-cache', 'Disable incremental file cache')
  .option('--baseline <path>', 'Compare against a saved JSON report; only report new findings')
  .action(async (opts: {
    config?: string;
    format: string;
    out?: string;
    threshold?: string;
    failOn?: string;
    maxFindings?: string;
    failFileThreshold?: string;
    verbose?: boolean;
    dir?: string;
    listRules?: boolean;
    watch?: boolean;
    concurrency?: string;
    cache?: boolean;
    baseline?: string;
  }) => {
    // ── --list-rules ──────────────────────────────────────────────────────
    if (opts.listRules) {
      const formats = opts.format.split(',').map(f => f.trim());
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

    // Load config file (includes env var overrides)
    const fileConfig = loadConfig(opts.config, cwd);

    // CLI options override config file and env vars
    const formats = opts.format.split(',').map(f => f.trim()) as OutputFormat[];

    const config: AuditConfig = {
      ...fileConfig,
      formats,
      threshold: opts.threshold ? parseInt(opts.threshold, 10) : fileConfig.threshold,
      out: opts.out ?? fileConfig.out,
      failOn: (opts.failOn as FailOn) ?? fileConfig.failOn,
      maxFindings: opts.maxFindings ? parseInt(opts.maxFindings, 10) : fileConfig.maxFindings,
      failFileThreshold: opts.failFileThreshold
        ? parseInt(opts.failFileThreshold, 10)
        : fileConfig.failFileThreshold,
      verbose: opts.verbose ?? fileConfig.verbose,
      concurrency: opts.concurrency ? parseInt(opts.concurrency, 10) : fileConfig.concurrency,
      cache: opts.cache, // commander sets false for --no-cache, undefined when not passed
      baseline: opts.baseline ?? fileConfig.baseline,
    };

    if (config.verbose) {
      console.log(`Scanning: ${cwd}`);
      console.log(`Threshold: ${config.threshold}`);
      console.log(`Formats: ${config.formats.join(', ')}`);
      if (config.cache !== false) console.log('Cache: enabled (.hound-cache.json)');
      if (config.plugins?.length) console.log(`Plugins: ${config.plugins.join(', ')}`);
      if (config.baseline) console.log(`Baseline: ${config.baseline}`);
    }

    // ── --watch mode ──────────────────────────────────────────────────────
    if (opts.watch) {
      await runWatchMode(cwd, config, formats);
      return;
    }

    // ── Single scan ───────────────────────────────────────────────────────
    let result;
    const jsonlLines: string[] = [];
    const onFinding = formats.includes('jsonl')
      ? (f: Finding) => { jsonlLines.push(JSON.stringify(f)); }
      : undefined;

    try {
      result = await runScan(cwd, config, onFinding);
    } catch (err) {
      console.error('Error during scan:', err);
      process.exit(1);
    }

    // ── Baseline diff ─────────────────────────────────────────────────────
    if (config.baseline) {
      result = applyBaseline(result, config.baseline);
    }

    // Console report always prints (unless only jsonl/json/sarif requested)
    if (formats.includes('console') || formats.length === 0) {
      printConsoleReport(result, config.verbose);
    }

    // JSON report
    if (formats.includes('json')) {
      const json = buildJsonReport(result);
      const outPath = config.out ? `${config.out}.json` : path.join(cwd, 'hound-results.json');
      fs.writeFileSync(outPath, json, 'utf8');
      console.log(`JSON report written to: ${outPath}`);
    }

    // SARIF report
    if (formats.includes('sarif')) {
      const sarif = buildSarifReport(result);
      const outPath = config.out
        ? (config.out.endsWith('.sarif') ? config.out : `${config.out}.sarif`)
        : path.join(cwd, 'results.sarif');
      fs.writeFileSync(outPath, sarif, 'utf8');
      console.log(`SARIF report written to: ${outPath}`);
    }

    // GitHub Annotations formatter
    if (formats.includes('github-annotations')) {
      const annotations = buildGithubAnnotationsReport(result);
      if (annotations) console.log(annotations);
    }

    // Markdown report
    if (formats.includes('markdown')) {
      const md = buildMarkdownReport(result);
      const outPath = config.out
        ? (config.out.endsWith('.md') ? config.out : `${config.out}.md`)
        : path.join(cwd, 'hound-report.md');
      fs.writeFileSync(outPath, md, 'utf8');
      console.log(`Markdown report written to: ${outPath}`);
    }

    // HTML report
    if (formats.includes('html')) {
      const html = buildHtmlReport(result);
      const outPath = config.out
        ? (config.out.endsWith('.html') ? config.out : `${config.out}.html`)
        : path.join(cwd, 'hound-report.html');
      fs.writeFileSync(outPath, html, 'utf8');
      console.log(`HTML report written to: ${outPath}`);
    }

    // CSV report
    if (formats.includes('csv')) {
      const csv = buildCsvReport(result);
      const outPath = config.out
        ? (config.out.endsWith('.csv') ? config.out : `${config.out}.csv`)
        : path.join(cwd, 'hound-report.csv');
      fs.writeFileSync(outPath, csv, 'utf8');
      console.log(`CSV report written to: ${outPath}`);
    }

    // JUnit XML report
    if (formats.includes('junit')) {
      const junit = buildJunitReport(result);
      const outPath = config.out
        ? (config.out.endsWith('.xml') ? config.out : `${config.out}.xml`)
        : path.join(cwd, 'hound-report.xml');
      fs.writeFileSync(outPath, junit, 'utf8');
      console.log(`JUnit XML report written to: ${outPath}`);
    }

    // JSONL report (findings already streamed; write to file if --out set)
    if (formats.includes('jsonl')) {
      const jsonlOutput = jsonlLines.join('\n');
      if (config.out) {
        const outPath = config.out.endsWith('.jsonl') ? config.out : `${config.out}.jsonl`;
        fs.writeFileSync(outPath, jsonlOutput, 'utf8');
        console.log(`JSONL report written to: ${outPath}`);
      } else {
        // Stream to stdout
        if (jsonlLines.length > 0) console.log(jsonlOutput);
      }
    }

    // Exit codes:
    // 0 = passed
    // 1 = unhandled error (handled above with catch)
    // 2 = threshold breached (score >= threshold)
    // 3 = failOn violation
    if (!result.passed) {
      const thresholdFailed = result.repoScore >= config.threshold || result.fileThresholdBreached;
      const failOnFailed = config.failOn != null && (() => {
        const sev = config.failOn!;
        if (sev === 'critical') return result.allFindings.some(f => f.severity === 'critical');
        if (sev === 'high') return result.allFindings.some(f => f.severity === 'high' || f.severity === 'critical');
        if (sev === 'medium') return result.allFindings.some(f => f.severity !== 'low');
        return false;
      })();

      if (failOnFailed) process.exit(3);
      if (thresholdFailed) process.exit(2);
      process.exit(2); // fallback
    }
    process.exit(0);
  });

// ── baseline diff ─────────────────────────────────────────────────────────────

function applyBaseline(result: ScanResult, baselinePath: string): ScanResult {
  let baselineFindings: Finding[] = [];
  try {
    const raw = JSON.parse(fs.readFileSync(path.resolve(baselinePath), 'utf8')) as ScanResult;
    baselineFindings = raw.allFindings ?? [];
  } catch {
    console.warn(`Warning: could not load baseline from ${baselinePath}; reporting all findings`);
    return result;
  }

  // A finding is "known" if baseline has same rule ID on same file
  const knownKeys = new Set(baselineFindings.map(f => `${f.id}:${f.file}`));
  const newFindings = result.allFindings.filter(f => !knownKeys.has(`${f.id}:${f.file}`));
  const resolvedCount = baselineFindings.filter(f => !result.allFindings.some(r => r.id === f.id && r.file === f.file)).length;

  console.log(`Baseline: ${baselineFindings.length} known · ${newFindings.length} new · ${resolvedCount} resolved`);

  // Rebuild result with only new findings
  const newFiles = result.files
    .map(fr => {
      const filtered = fr.findings.filter(f => !knownKeys.has(`${f.id}:${f.file}`));
      return filtered.length > 0 ? { ...fr, findings: filtered } : null;
    })
    .filter((fr): fr is NonNullable<typeof fr> => fr !== null);

  const rawTotal = newFiles.reduce((s, f) => s + f.fileScore, 0);
  const repoScore = Math.min(100, rawTotal);

  return {
    ...result,
    files: newFiles,
    allFindings: newFindings,
    repoScore,
    scoreLabel: result.repoScore < 30 ? 'low' : result.repoScore < 60 ? 'medium' : result.repoScore < 80 ? 'high' : 'critical',
    passed: repoScore < result.threshold,
  };
}

// ── watch mode implementation ─────────────────────────────────────────────────

async function runWatchMode(cwd: string, config: AuditConfig, formats: OutputFormat[]): Promise<void> {
  const chokidar = await import('chokidar');

  // Initial full scan
  let result = await runScan(cwd, config);
  printConsoleReport(result, config.verbose);

  // Track findings by file for delta detection
  const prevFindings = new Map<string, string[]>();
  for (const fr of result.files) {
    prevFindings.set(fr.file, fr.findings.map(f => `${f.id}:${f.lineStart}`));
  }

  console.log('\n[watching for changes… Ctrl+C to exit]\n');

  const watcher = chokidar.watch(config.include.map(g => path.join(cwd, g)), {
    cwd,
    ignored: config.exclude,
    ignoreInitial: true,
    persistent: true,
  });

  const handleChange = async (filePath: string) => {
    const absPath = path.isAbsolute(filePath) ? filePath : path.join(cwd, filePath);
    console.log(`\n[changed] ${absPath}`);

    try {
      result = await runScan(cwd, config);
      printConsoleReport(result, config.verbose);

      // Show delta for changed file
      const newFr = result.files.find(f => f.file === absPath);
      const newKeys = newFr ? newFr.findings.map(f => `${f.id}:${f.lineStart}`) : [];
      const oldKeys = prevFindings.get(absPath) ?? [];
      const added = newKeys.filter(k => !oldKeys.includes(k));
      const removed = oldKeys.filter(k => !newKeys.includes(k));
      if (added.length > 0) console.log(`  +${added.length} new finding(s)`);
      if (removed.length > 0) console.log(`  -${removed.length} resolved finding(s)`);
      prevFindings.set(absPath, newKeys);
    } catch (err) {
      console.error('Error during re-scan:', err);
    }

    console.log('\n[watching for changes… Ctrl+C to exit]\n');
  };

  watcher.on('change', handleChange);
  watcher.on('add', handleChange);

  // Keep process alive
  process.on('SIGINT', async () => {
    await watcher.close();
    process.exit(0);
  });

  void formats; // suppress unused warning
}

program.parse(process.argv);
