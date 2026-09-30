# ContextHound

> Static analysis tool that scans your codebase for LLM prompt-injection and multimodal security vulnerabilities. Runs offline, no API calls required.

[![CI](https://github.com/IulianVOStrut/ContextHound/actions/workflows/context-hound.yml/badge.svg)](https://github.com/IulianVOStrut/ContextHound/actions/workflows/context-hound.yml)
[![npm](https://img.shields.io/npm/v/context-hound)](https://www.npmjs.com/package/context-hound)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.19-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The ContextHound ecosystem

ContextHound is available across your entire development and browsing workflow:

| Tool | What it does | Install |
|---|---|---|
| **CLI / npm package** | Scans your codebase for prompt injection vulnerabilities. Integrates with GitHub Actions, outputs SARIF, JSON, HTML, and more. | `npm install -g context-hound` |
| **VS Code extension** | Inline findings as you code, code actions, output channel, status bar. | [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=ContextHound.contexthound) |
| **Browser extension** | Real-time scan pill on any AI chat interface, DevTools panel for LLM API traffic, popup scanner. Chrome and Firefox. | Firefox: [Install free](https://addons.mozilla.org/firefox/addon/contexthound/) · Chrome: awaiting review · [source](https://github.com/IulianVOStrut/ContextHound-Extensions) |

---

## ☕ Support the project

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/D1D01UKFNS)
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/I_VO_S)

---

## Why ContextHound?

As LLM-powered applications become common in production codebases, prompt injection has emerged as one of the most exploitable attack surfaces; most security scanners have no awareness of it.

ContextHound brings static analysis to your prompt layer:

- Catches **injection paths** before they reach a model
- Flags **leaked credentials and internal infrastructure** embedded in prompts
- Detects **jailbreak-susceptible wording** in your system prompts
- Identifies **unconstrained agentic tool use** that could be weaponised
- Detects **RAG corpus poisoning** and retrieved content injected as system instructions
- Catches **encoding-based smuggling** (Base64 instructions that bypass string filters)
- Flags **unsafe LLM output consumption**: JSON without schema validation and Markdown without sanitization
- Detects **multimodal attack surfaces**: user-supplied image URLs to vision APIs, path traversal via vision message file reads, transcription output fed into prompts, and OCR text injected into system instructions
- Flags **agentic risks**: unbounded agent loops, unvalidated memory writes, plan injection, and tool parameters receiving system-prompt content
- Rewards **good security practice**: mitigations in your prompts reduce your score

It fits into your existing workflow as a CLI command, an `npm` script, a pre-commit hook or a GitHub Action. It makes no network calls and has four small runtime dependencies.

---

## Features

| | |
|---|---|
| **122 security rules** | Across 15 families: injection, exfiltration, jailbreak, unsafe tool use, command injection, RAG poisoning, encoding and hidden content, output handling, multimodal, agent skills, agentic, MCP, supply chain, resource consumption, persistence |
| **OWASP mapping** | Every rule carries OWASP Top 10 for LLM Applications (2025) and Agentic Applications (2026) IDs, shown in `hound explain`, `--verbose`, SARIF tags and all reports |
| **Numeric risk score (0-100)** | Normalized repo-level score with low, medium, high and critical thresholds |
| **Mitigation detection** | Explicit safety language in your prompts reduces your score |
| **9 output formats** | Console, JSON, SARIF, GitHub Annotations, Markdown, JSONL streaming, interactive HTML, CSV and JUnit XML |
| **GitHub Action included** | Fails CI on risky changes, uploads SARIF to Code Scanning and can keep a summary comment on the pull request |
| **Autofix** | `hound fix` previews and removes hidden Unicode characters (ENC-002 to ENC-005) |
| **Multi-language scanning** | Detects LLM API usage in Python, Go, Rust, Java, C#, PHP, Ruby, Swift, Kotlin, Vue and Bash, not just TypeScript and JavaScript |
| **Rule filtering** | `excludeRules`/`includeRules` with prefix-glob syntax (`CMD-*`); `minConfidence` filter |
| **Incremental cache** | `.hound-cache.json` skips unchanged files on re-runs; `--no-cache` to disable |
| **Respects `.gitignore`** | Files git ignores are skipped; `.houndignore` adds exclusions in the same syntax |
| **Plugin system** | Load custom rules from local `.js` files via `"plugins": ["./my-rule.js"]` in config |
| **Baseline / diff mode** | `--baseline results.json` reports and fails only on findings absent from a prior scan; `--diff` scans only changed files |
| **Watch mode** | `--watch` re-scans on file changes and shows delta findings |
| **Parallel scanning** | Concurrent file processing (`--concurrency <n>`, default 8) |
| **Fully offline** | No API calls and no telemetry |

---

## Installation

**Global install** adds the `hound` command to your PATH:

```bash
npm install -g context-hound
```

**Per-project install** is scoped to one repo and runs via `npx hound` or an npm script:

```bash
npm install --save-dev context-hound
```

**Without installing**, `npx` fetches and runs the package:

```bash
npx context-hound scan --dir .
```

---

## Quick Start

```bash
# Scaffold a config file
hound init

# Scan your project
hound scan --dir ./my-ai-project

# Or via npm script (scans current directory)
npm run hound

# Verbose output, shows remediations and confidence levels
hound scan --verbose

# Fail the build on any critical finding
hound scan --fail-on critical

# Export JSON and SARIF reports
hound scan --format console,json,sarif --out results

# GitHub Annotations (for CI step summaries)
hound scan --format github-annotations

# Markdown report with findings tables
hound scan --format markdown --out report

# Stream findings as JSONL (one JSON object per line)
hound scan --format jsonl | jq '.severity'

# List all rules
hound scan --list-rules

# Explain a rule (or a rule family by prefix)
hound explain INJ-001
hound explain PST --format json

# Fast PR gate: scan only files changed vs. origin/main
hound scan --diff

# Interactive HTML report (self-contained, open in browser)
hound scan --format html --out report

# Re-scan on file changes
hound scan --watch

# Parallel scanning (default is 8; tune for your machine)
hound scan --concurrency 16

# Disable incremental cache for a clean run
hound scan --no-cache

# Also scan files that git ignores (skipped by default)
hound scan --no-gitignore

# Preview, then remove, hidden Unicode characters flagged by ENC-002 to ENC-005
hound fix
hound fix --write

# Baseline mode: only report findings new since the last saved scan
hound scan --format json --out baseline          # save a baseline
hound scan --baseline baseline.json             # compare future scans against it

# Load a custom rule from a local plugin file
hound scan  # plugin declared in .contexthoundrc.json "plugins" field

# Only run high-confidence rules
hound scan --config .contexthoundrc.json  # set minConfidence: "high"

# Fail if any single file scores >= 40
hound scan --fail-file-threshold 40

# Scan files up to 5 MB (default limit is 1 MiB; 0 = no limit)
hound scan --max-file-size 5242880
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Passed: score below threshold and no `failOn` violation |
| `1` | Unhandled error or bad arguments |
| `2` | Threshold breached: repo score at or above the threshold, or a file over `failFileThreshold` |
| `3` | `--fail-on` violation: a finding at or above that severity |

---

## GitHub Actions

Use the ContextHound Action to scan on every push and pull request, upload findings to GitHub Code Scanning, and block merges on risky changes:

```yaml
# .github/workflows/contexthound.yml
name: Prompt Audit

on: [push, pull_request]

jobs:
  hound:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # SARIF upload to Code Scanning

    steps:
      - uses: actions/checkout@v7

      - uses: IulianVOStrut/ContextHound@v2
        with:
          fail-on: high
```

Findings appear in your repository's **Security > Code scanning** tab and as annotations on the pull request.

| Input | Default | Description |
|-------|---------|-------------|
| `version` | the release matching the Action | Exact `context-hound` npm version to run |
| `dir` | `.` | Directory to scan |
| `config` | | Path to a `.contexthoundrc.json` |
| `threshold` | config or `60` | Fail when the repo score is at or above this value |
| `fail-on` | | Fail on any finding of this severity or above: `critical`, `high`, `medium` |
| `min-confidence` | | Only report rules at or above `low`, `medium` or `high` confidence |
| `diff` | | Scan only files changed vs. this git ref, e.g. `origin/${{ github.base_ref }}` (needs `fetch-depth: 0` on checkout) |
| `preset` | | Comma-separated rule presets, e.g. `owasp-llm-top10` |
| `sarif-out` | `results.sarif` | Where to write the SARIF report |
| `upload-sarif` | `true` | Upload the report to Code Scanning |
| `node-version` | | Set up this Node.js version first (default: use the runner's Node.js) |
| `comment` | `false` | On pull requests, post a summary comment and update it on later runs (needs `pull-requests: write`) |
| `github-token` | `github.token` | Token used for the pull request comment |

Outputs: `score`, `findings`, `passed` and `sarif-file`, for use in later steps.

**Pull request comments.** With `comment: true` the Action keeps one ContextHound comment on the pull request up to date: pass or fail, score, counts per severity and a table of findings linked to the exact lines of the head commit. Combine it with `diff` so the comment lists only what the pull request changed:

```yaml
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: IulianVOStrut/ContextHound@v2
        with:
          diff: origin/${{ github.base_ref }}
          comment: true
          fail-on: high
```

Scanned content (paths, evidence) is rendered as code, so a malicious pull request cannot inject links, HTML or @mentions into the comment. Only comments posted by `github-actions[bot]` are ever edited. Pull requests from forks get a read-only token, so there the Action logs a warning instead of commenting.

For stricter supply-chain hygiene, pin the Action to a release commit SHA instead of `@v2`.

**Without the Action**, install the CLI directly:

```yaml
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-node@v7
        with:
          node-version: '22'

      - run: npm install -g context-hound@2.2.1

      - run: hound scan --format console,sarif,github-annotations --out results

      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

The `github-annotations` format adds inline annotations to the pull request and writes a summary table to the GitHub step summary.

---

## Configuration

Run `hound init` to scaffold a `.contexthoundrc.json`, or create one manually:

```json
{
  "$schema": "https://raw.githubusercontent.com/IulianVOStrut/ContextHound/main/schema/contexthoundrc.schema.json",
  "include": ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.rs", "**/*.md", "**/*.txt", "**/*.yaml"],
  "exclude": [
    "**/node_modules/**",
    "**/dist/**",
    "**/tests/**",
    "**/attacks/**"
  ],
  "threshold": 60,
  "formats": ["console", "sarif"],
  "out": "results",
  "verbose": false,
  "failOn": "critical",
  "maxFindings": 50,
  "maxFileSize": 1048576,
  "excludeRules": ["JBK-002"],
  "includeRules": [],
  "minConfidence": "medium",
  "failFileThreshold": 80,
  "concurrency": 8,
  "cache": true,
  "plugins": ["./rules/my-custom-rule.js"],
  "baseline": "./baseline.json"
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `include` | prompt, Markdown, text, YAML and JSON files, plus `ts tsx mts cts js jsx mjs cjs vue py go rs java kt kts cs php rb swift sh bash hs` | Glob patterns to scan. Run `hound init` to see the full list |
| `exclude` | dependency, build and virtualenv directories (`node_modules`, `dist`, `build`, `vendor`, `target`, `.venv`, `venv`, `__pycache__`, `.next`, ...), lockfiles, minified JS and ContextHound's own reports | Glob patterns to ignore. Report files written with `--out` are excluded automatically |
| `threshold` | `60` | Fail if repo score is at or above this value (exit code 2) |
| `formats` | `["console"]` | Output formats: `console`, `json`, `sarif`, `github-annotations`, `markdown`, `jsonl`, `html`, `csv`, `junit`. `--format` overrides this |
| `out` | auto | Base path for file output |
| `verbose` | `false` | Show remediations and confidence per finding |
| `failOn` | unset | Exit code 3 on first finding of: `critical`, `high`, or `medium` |
| `maxFindings` | unset | Stop after N findings |
| `maxFileSize` | `1048576` | Skip files larger than this many bytes (1 MiB). Skipped files are listed on stderr and in the JSON report's `skippedFiles`, so they are never dropped silently. `0` disables the limit. Also `--max-file-size <bytes>` |
| `excludeRules` | `[]` | Rule IDs or prefix globs to skip (e.g. `"CMD-*"`, `"JBK-002"`) |
| `includeRules` | `[]` | Run only these rule IDs (empty = run all) |
| `minConfidence` | unset | Skip rules below this confidence: `low`, `medium`, or `high` |
| `failFileThreshold` | unset | Fail (exit code 2) if any single file scores at or above this value |
| `concurrency` | `8` | Max files processed in parallel |
| `cache` | `true` | Enable incremental scan cache (`.hound-cache.json`); set `false` or use `--no-cache` to disable |
| `gitignore` | `true` | Skip files git ignores (nested `.gitignore` files, `.git/info/exclude`, global excludes); tracked files are always scanned. Set `false` or use `--no-gitignore` to scan them |
| `plugins` | `[]` | Paths to local `.js` rule plugins; each must export a `Rule` or `Rule[]` |
| `baseline` | unset | Path to a previous JSON report; only findings absent from the baseline are reported |

The config file is validated on every run. Unknown options (with a "did you mean" suggestion), wrong types, out-of-range numbers, invalid JSON and a missing `--config` path are all errors (exit code 1) rather than being silently ignored, because an ignored option can quietly disable a CI gate. The `$schema` line gives editors autocomplete and inline validation; keys starting with `_` are allowed for comments.

### Config file locations and `extends`

Without `--config` or `HOUND_CONFIG`, ContextHound uses the first of these it finds in the scan directory: `.contexthoundrc.json`, `.contexthoundrc` (JSON), or a `"contexthound"` section in `package.json`.

`extends` builds on other configs. Entries are applied in order, then the file's own keys; arrays replace rather than merge.

```json
{
  "extends": ["contexthound:recommended", "./config/hound-team.json"],
  "excludeRules": ["DOS-*"]
}
```

| Value | Meaning |
|-------|---------|
| `contexthound:recommended` | `failOn: "high"`, `minConfidence: "medium"` |
| `contexthound:strict` | `failOn: "medium"`, `failFileThreshold: 60` |
| `./path/file.json` | A JSON file, relative to the config that extends it |
| `@scope/pkg/contexthound.json` | A JSON file inside an installed npm package |

Only JSON configs are supported, on purpose: a JavaScript config would run code from the repository being scanned, which in CI can be an untrusted pull request.

### Prompt files and documentation

Markdown and text files are split into two groups:

- **Prompt files** get every rule: `*.prompt` and `*.prompt.*` files, files whose name mentions prompt, instruction, system message or persona, files in `prompts/`, `instructions/`, `personas/` or `skills/` folders, and agent instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `*.mdc`, `.cursor/rules/`, `.claude/`, `.github/copilot-instructions.md`, `.github/prompts/`, `llms.txt`, `SKILL.md`).
- **Everything else** (README, changelogs, guides, datasets) is treated as documentation and only gets rules that indicate a real problem in any text: hidden Unicode characters, real secret values, and instructions hidden in HTML comments. A README that mentions an "API key" or quotes an attack phrase is not a finding.

If your prompts live somewhere else, name or place them so they match, or scan them as `.prompt` files.

### Environment variable overrides

All key settings can be overridden at runtime without editing the config file:

| Variable | Overrides |
|----------|-----------|
| `HOUND_THRESHOLD` | `threshold` |
| `HOUND_FAIL_ON` | `failOn` |
| `HOUND_MIN_CONFIDENCE` | `minConfidence` |
| `HOUND_VERBOSE` | `verbose` (truthy: `1`, `true`, `yes`) |
| `HOUND_CONFIG` | path to config file |

### `.houndignore` and `.gitignore`

Files that git ignores are skipped by default. Inside a repository ContextHound asks git, so nested `.gitignore` files, `.git/info/exclude` and your global excludes all apply, and tracked files are always scanned even if they match an ignore pattern. Outside a repository, the scan directory's own `.gitignore` is used. Pass `--no-gitignore` (or set `"gitignore": false`) to scan ignored files too.

A `.houndignore` file in the scan directory adds exclusions without editing `.contexthoundrc.json`. It uses `.gitignore` syntax: `secrets/` skips a directory, `*.test.ts` matches at any depth, `!keep.test.ts` re-includes a file, and lines starting with `#` are comments. It applies even with `--no-gitignore`.

### Inline suppressions

Silence a known false positive directly in the source instead of disabling a rule for the whole repository. Directives are recognised in **any** file type (the surrounding comment syntax doesn't matter):

```ts
// hound-disable-next-line INJ-001 -- userInput is a validated enum
const prompt = `Summarise the ${userInput} report`;

const cmd = run(`${shell}`); // hound-disable-line CMD-001

// hound-disable RAG-007 -- trusted internal corpus only
context.push(doc.metadata.title);
context.push(doc.metadata.author);
// hound-enable RAG-007
```

- `hound-disable-line [RULE...]`: suppress findings on the same line
- `hound-disable-next-line [RULE...]`: suppress findings on the following line
- `hound-disable [RULE...]` … `hound-enable [RULE...]`: suppress a block (auto-closed at end of file)
- `hound-disable-file [RULE...]` anywhere in a file: suppress findings throughout that file (for example a collection of attack samples)
- Omit rule IDs to suppress **all** rules at that location; list one or more (space/comma separated) to scope it
- Text after `--` is a free-form justification, surfaced in reports

Run with `--report-unused-suppressions` to list directives that no longer match any finding, so dead suppressions can be cleaned up:

```bash
hound scan --report-unused-suppressions
```

### Rule presets

Enable a curated subset of rules with `--preset` instead of listing IDs. Presets union with any `includeRules` you already have, and several can be combined:

```bash
hound scan --preset owasp-llm-top10
hound scan --preset owasp-agentic
hound scan --preset mcp,agentic
hound scan --list-presets          # show all presets and their rule patterns
```

| Preset | Rules |
|--------|-------|
| `owasp-llm-top10` | Every rule mapped to an OWASP LLM Top 10 (2025) category (LLM01 to LLM10) |
| `owasp-agentic` | Every rule mapped to an OWASP Agentic Top 10 (2026) category (ASI01 to ASI10) |
| `injection` | INJ, RAG, ENC |
| `jailbreak` | JBK |
| `exfiltration` | EXF |
| `agentic` | AGT, MCP, TOOL |
| `mcp` | MCP |
| `supply-chain` | SCH |
| `prompt-files` | INJ, JBK, EXF, ENC, SKL |

### pre-commit hook

ContextHound ships a [pre-commit](https://pre-commit.com) hook. Add it to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/IulianVOStrut/ContextHound
    rev: v2.2.1
    hooks:
      - id: contexthound
        # optional: scan only changed files and fail on high-severity findings:
        # args: ["--diff", "HEAD", "--fail-on", "high"]
```

### Custom rule plugins

Any `.js` file that exports a `Rule` or `Rule[]` can be loaded as a plugin:

```js
// my-rule.js
module.exports = {
  id: 'CUSTOM-001',
  title: 'Proprietary data pattern in prompt',
  severity: 'high',
  confidence: 'high',
  category: 'injection',
  remediation: 'Remove internal identifiers from prompts.',
  check(prompt) {
    if (prompt.text.includes('INTERNAL_PATTERN')) {
      return [{ evidence: 'INTERNAL_PATTERN', lineStart: 1, lineEnd: 1 }];
    }
    return [];
  },
};
```

Reference it in `.contexthoundrc.json`:
```json
{ "plugins": ["./my-rule.js"] }
```

Plugin rules are subject to the same `excludeRules`, `includeRules`, and `minConfidence` filters as built-in rules. They run on every scanned file, including general documentation; set `docs: false` on a rule to limit it to prompt files and code.

### Baseline / diff mode

Save a baseline after an initial scan, then only report findings that are new in subsequent scans:

```bash
# Save baseline
hound scan --format json --out baseline

# Future scans only report new issues
hound scan --baseline baseline.json
```

Findings are matched by a fingerprint of rule, file, evidence text and occurrence, so line shifts elsewhere in a file don't raise false "new" findings, while a second instance of a rule in an already-baselined file is still reported. File paths in every report are relative to the git repository root (or the scan directory outside git), so a baseline saved on a laptop also matches in CI. Baselines saved by older versions still work.

### Changed-files-only (`--diff`)

For fast pull-request gates, scan only the files that changed relative to a git ref instead of the whole tree:

```bash
hound scan --diff               # vs. origin/main (default)
hound scan --diff main          # vs. a named branch
hound scan --diff HEAD~5        # vs. an arbitrary ref
```

Covers committed, staged, unstaged, and untracked-but-not-ignored files. If git is unavailable or the ref can't be resolved (e.g. a shallow CI clone), ContextHound prints a warning and falls back to a full scan rather than silently passing. Combine with `--baseline` for findings-level diffing, or use `--diff` alone for the fastest PR feedback.

### Library usage

ContextHound can also be used from Node.js. Importing it has no side effects, and every formatter returns a string without writing files:

```js
const { loadConfig, runScan, buildSarifReport } = require('context-hound');

const config = loadConfig(undefined, process.cwd());
const result = await runScan(process.cwd(), config);
console.log(result.repoScore, result.passed, result.failures);
fs.writeFileSync('results.sarif', buildSarifReport(result));
```

The runtime guard is available as `require('context-hound/runtime')` and the config JSON Schema as `context-hound/schema.json`.

```js
const { createGuard } = require('context-hound/runtime');

const guard = createGuard({ policy: { critical: 'block', high: 'warn' } });
const answer = await guard.wrap(messages, () => client.chat.completions.create({ model, messages }));
```

By default the guard runs only the rules that make sense on live message content (`RUNTIME_DEFAULT_RULES`: jailbreak phrases, encoding and steganography, system-prompt extraction, secret values and hidden comment instructions), so ordinary user messages are not blocked by code-oriented rules. Set `policy.includeRules` to choose your own set; rules passed as `extraRules` always run.

---

## Risk Scoring

Each finding carries **risk points**:

```
risk_points = severity_weight × confidence_multiplier
```

Severity weights are 50 (critical), 30 (high), 15 (medium) and 5 (low); confidence multiplies by 1.0 (high), 0.75 (medium) or 0.5 (low).

Points are combined, not summed, so scores rise with risk without saturating after a couple of findings:

```
combine(p1..pn) = 100 × (1 − (1 − p1/100) × … × (1 − pn/100))
```

- **File score:** each rule counts once per file (at its highest points), and different rules are combined. Two unrelated critical findings in one file score 75.
- **Repo score:** files are sorted worst first and each further file counts half as much as the one before, so the score reflects how serious the worst problems are rather than how large the repository is.

| Score | Level | Suggested action |
|-------|-------|-----------------|
| 0-29 | 🟢 Low | No action required |
| 30-59 | 🟡 Medium | Review before merging |
| 60-79 | 🟠 High | Fix before merging |
| 80-100 | 🔴 Critical | Block deployment |

For CI gates, `--fail-on high` (or `critical`) is the most predictable control: it fails on any new finding of that severity regardless of score. The score and `--threshold` are best used as a trend signal.

If your prompts include explicit safety language (input delimiters, refusal-to-reveal instructions, tool allowlists), risk points for the findings those mitigations address are reduced.

---

## Rules

<!-- rules:start -->
<!-- Generated from the rule registry by `npm run docs`. Do not edit by hand. -->

122 rules in 15 families. Run `hound explain <RULE-ID>` for the full remediation, or `hound scan --list-rules` for the list in your terminal.

### Injection (INJ)

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| INJ-001 | High | Direct user input concatenation without delimiter | LLM01 |
| INJ-002 | Medium | Missing "treat user content as data" boundary language | LLM01 |
| INJ-003 | High | RAG context included without untrusted separator | LLM01 |
| INJ-004 | High | Tool/function instructions overridable by user content | LLM01, ASI01 |
| INJ-005 | High | Serialised user object interpolated into prompt | LLM01 |
| INJ-006 | Medium | HTML comment with hidden instructions in user-controlled content | LLM01 |
| INJ-007 | Medium | User input wrapped in code-fence delimiters without sanitizing the delimiter | LLM01 |
| INJ-008 | High | HTTP request data interpolated into system-role message template | LLM01 |
| INJ-009 | Critical | HTTP request body parsed as messages array (role injection) | LLM01 |
| INJ-010 | High | Plaintext role-label transcript built with untrusted input | LLM01 |
| INJ-011 | High | Browser DOM or URL source fed directly into LLM call | LLM01 |
| INJ-012 | High | Conversation history spread into messages array without sanitisation | LLM01, ASI06 |
| INJ-013 | High | Tool or function call result inserted into messages without sanitisation | LLM01, ASI01 |
| INJ-014 | High | LLM completion piped as user-role content into a subsequent LLM call | LLM01, ASI01, ASI07 |
| INJ-015 | High | Untrusted external input flows into a prompt (taint analysis) | LLM01 |
| INJ-016 | Critical | Template engine renders user-controlled string as template source | LLM01, LLM05 |

### Exfiltration (EXF)

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| EXF-001 | High | Prompt references secrets, API keys, or credentials | LLM02 |
| EXF-002 | Critical | Prompt instructs model to reveal system prompt or hidden instructions | LLM07 |
| EXF-003 | High | Prompt indicates access to confidential or private data | LLM02 |
| EXF-004 | High | Prompt includes internal URLs or infrastructure references | LLM02 |
| EXF-005 | High | Sensitive variable encoded as Base64 in output | LLM02 |
| EXF-006 | High | Full prompt or message array logged without redaction | LLM02 |
| EXF-007 | Critical | Secret value embedded in prompt alongside "never reveal" instruction | LLM02, LLM07 |
| EXF-008 | Critical | Hardcoded secret value in prompt, code or documentation | LLM02 |

### Jailbreak (JBK)

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| JBK-001 | Critical | Known jailbreak phrase detected | LLM01 |
| JBK-002 | High | Weak safety language that can be overridden | LLM01 |
| JBK-003 | High | Role-play escape hatch that undermines safety | LLM01 |
| JBK-004 | High | Agent instructed to act without confirmation or human review | LLM06, ASI09 |
| JBK-005 | High | Evidence-erasure or cover-tracks instruction in prompt | LLM01, ASI10 |
| JBK-006 | High | Policy-legitimacy framing combined with unsafe action request | LLM01 |
| JBK-007 | High | Model identity spoofing combined with safety bypass | LLM01, ASI09 |
| JBK-008 | High | Prompt compression attack | LLM01 |
| JBK-009 | High | Nested instruction injection via safe-framing wrapper | LLM01 |
| JBK-010 | Critical | Meta-command activation keyword detected | LLM01 |
| JBK-011 | High | Instruction dismissal: prior rules framed as obsolete or superseded | LLM01 |
| JBK-012 | High | Priority downgrade: system instructions demoted below user input | LLM01 |
| JBK-013 | High | Training or safety constraint explicitly declared void | LLM01 |

### Unsafe tool use (TOOL)

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| TOOL-001 | Critical | Unbounded tool execution (run any command / browse anywhere) | LLM06, ASI02 |
| TOOL-002 | Medium | No tool allowlist or usage policy defined | LLM06, ASI02 |
| TOOL-003 | High | Code execution without sandboxing mention | LLM06, ASI05 |
| TOOL-004 | Critical | Tool description or schema field sourced from user-controlled variable | LLM01, ASI02 |
| TOOL-005 | Critical | Tool name or endpoint URL sourced from user-controlled input | LLM06, ASI02 |

### Command injection (CMD)

Vulnerable patterns in the code around AI tools, where a successful prompt injection can escalate into command execution. Informed by the CVEs Cyera Research Labs found in Google's Gemini CLI (2025), plus reverse-shell patterns.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| CMD-001 | Critical | Shell command constructed with unsanitised variable interpolation | LLM05, ASI05 |
| CMD-002 | High | Incomplete command substitution filtering: backtick bypass possible | LLM05, ASI05 |
| CMD-003 | High | File path from glob or directory listing used in shell command | LLM05, ASI05 |
| CMD-004 | Critical | Python subprocess.run/call with shell=True and user-controlled variable | LLM05, ASI05 |
| CMD-005 | Critical | PHP shell_exec/system/passthru/exec with user-controlled argument | LLM05, ASI05 |
| CMD-006 | Critical | Reverse shell via bash /dev/tcp file descriptor redirect | LLM03, ASI05 |
| CMD-007 | Critical | Named pipe reverse shell: mkfifo piped to shell or netcat | LLM03, ASI05 |
| CMD-008 | Critical | Netcat/ncat with execute flag spawning an interactive shell | LLM03, ASI05 |

### RAG poisoning (RAG)

Architectural mistakes in retrieval-augmented generation pipelines that let retrieved or ingested content override system-level instructions.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| RAG-001 | High | Retrieved content injected as system-role message | LLM01 |
| RAG-002 | High | Instruction-like phrases in document ingestion pipeline | LLM01, LLM04 |
| RAG-003 | High | Agent memory written directly from user-controlled input | LLM04, ASI06 |
| RAG-004 | Medium | Prompt instructs model to treat retrieved context as highest priority | LLM01, ASI01 |
| RAG-005 | Medium | Provenance-free retrieval: chunks inserted into prompt without source metadata check | LLM08 |
| RAG-006 | High | No ACL or trust-tier filter applied before retrieval enters the prompt | LLM08 |
| RAG-007 | High | Document metadata field interpolated into prompt without sanitisation | LLM01, LLM08 |

### Encoding and hidden content (ENC)

Encodings and invisible Unicode used to smuggle instructions past string filters and human review. `hound fix` removes the characters flagged by ENC-002 to ENC-005.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| ENC-001 | Medium | Base64 encoding of user-controlled variable near prompt construction | LLM01 |
| ENC-002 | High | Hidden Unicode control characters detected in prompt asset | LLM01 |
| ENC-003 | Critical | Unicode Tags block characters detected: steganographic injection risk | LLM01 |
| ENC-004 | High | Consecutive zero-width character sequence: covert encoding detected | LLM01 |
| ENC-005 | High | Unicode variation selector sequence: invisible payload encoding | LLM01 |
| ENC-006 | Medium | ROT13 or Caesar cipher applied near LLM context | LLM01 |

### Output handling (OUT)

How the application consumes model responses. Unsafe consumption turns a prompt-injection payload into an application-level exploit.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| OUT-001 | Critical | LLM JSON output parsed without schema validation | LLM05 |
| OUT-002 | Critical | LLM output rendered via Markdown or HTML without sanitization | LLM05, LLM02 |
| OUT-003 | Critical | LLM output used directly in exec(), eval(), or database query | LLM05, ASI05 |
| OUT-004 | Critical | Python eval() or exec() called with LLM-generated output | LLM05, ASI05 |
| OUT-005 | High | LLM output written to shared cache without validation: cache poisoning risk | LLM05, ASI06 |

### Multimodal (VIS)

Trust-boundary violations in vision, audio and OCR pipelines, where an attacker who controls an image, a recording or a scanned document can smuggle instructions into the model.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| VIS-001 | Critical | User-supplied image URL or base64 passed to vision API without validation | LLM01 |
| VIS-002 | Critical | User-supplied file path read into vision message (path traversal) | LLM02 |
| VIS-003 | High | Audio/video transcription output fed into prompt without sanitization | LLM01 |
| VIS-004 | High | OCR output interpolated into system instructions | LLM01 |

### Agent skills (SKL)

Targets `SKILL.md` files and Markdown files inside `skills/` directories: self-authoring, remote skill loading, injected instructions, unsafe command dispatch, sensitive paths, privilege claims and hardcoded credentials in frontmatter.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| SKL-001 | Critical | Skill instructs agent to write or modify skill files (self-authoring attack) | LLM06, ASI10 |
| SKL-002 | Critical | Skill instructs agent to fetch or load skills from an external URL | LLM03, ASI04 |
| SKL-003 | Critical | Prompt injection in skill body targeting agent core instructions | LLM01, ASI01 |
| SKL-004 | High | Skill frontmatter uses command-dispatch: tool with raw argument mode | LLM06, ASI05 |
| SKL-005 | High | Skill body instructs agent to access sensitive filesystem paths | LLM02, LLM06 |
| SKL-006 | High | Skill claims elevated privileges or instructs agent to bypass other skills | LLM06, ASI03 |
| SKL-007 | Critical | Hardcoded credential value in YAML frontmatter field | LLM02 |
| SKL-008 | Critical | Skill implements heartbeat C2: scheduled remote fetch overwrites skill instructions | LLM03, ASI04 |
| SKL-009 | Critical | Skill instructs agent to deny being an AI or adopt a deceptive human identity | LLM09, ASI09 |
| SKL-010 | Critical | Skill contains anti-scanner evasion targeting security auditing tools | ASI10 |
| SKL-011 | Critical | Skill injects instructions into agent identity files (SOUL.md / IDENTITY.md persistence) | ASI06, ASI10 |
| SKL-012 | High | Skill contains self-propagation instructions: SSH spread or curl-pipe-bash worm pattern | LLM03, ASI10 |
| SKL-013 | High | Skill instructs agent to execute autonomous financial transactions without user confirmation | LLM06, ASI09 |

### Agentic (AGT)

Risks specific to multi-step agents: unbounded loops, unvalidated memory writes, user input in planning prompts and inter-agent trust boundaries.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| AGT-001 | Critical | Tool call parameter receives system-prompt content | LLM07, ASI02 |
| AGT-002 | High | Agent loop with no iteration or timeout guard | LLM10, ASI08 |
| AGT-003 | High | Agent memory written from unvalidated LLM output | LLM04, ASI06 |
| AGT-004 | High | Plan injection: user input interpolated into agent planning prompt | LLM01, ASI01 |
| AGT-005 | Critical | Agent trusts claimed identity without cryptographic verification | ASI03 |
| AGT-006 | High | Raw agent output chained as input to another agent without validation | ASI07 |
| AGT-007 | Critical | Agent modifies its own system prompt, instructions, or tool list at runtime | LLM06, ASI10 |
| AGT-008 | Critical | Agent assumes IAM role or grants permissions based on LLM output (ASI03) | LLM06, ASI03 |
| AGT-009 | High | Agent loads tool or plugin from variable path or external URL at runtime (ASI04) | LLM03, ASI04 |
| AGT-010 | High | Raw agent output forwarded to another agent without trust boundary validation (ASI07) | ASI07 |
| AGT-011 | High | Agent step error silently swallowed: downstream steps proceed on bad state (ASI08) | ASI08 |

### Model Context Protocol (MCP)

Trust-boundary and supply-chain risks in MCP clients and servers: tool descriptions, transport URLs, event payloads and cross-server shared state can all carry injection or privilege-escalation payloads.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| MCP-001 | Critical | MCP tool description injected into LLM prompt without sanitization | LLM01, ASI01 |
| MCP-002 | High | MCP tool registered with dynamic name or description | ASI02 |
| MCP-003 | High | MCP sampling/createMessage handler without human approval guard | LLM06, ASI09 |
| MCP-004 | Medium | MCP transport URL constructed from variable | ASI02 |
| MCP-005 | High | MCP stdio transport uses shell:true | ASI02, ASI05 |
| MCP-006 | Critical | MCP confused deputy: auth token from MCP request forwarded to downstream API without re-validation | ASI03 |
| MCP-007 | High | Cross-MCP context poisoning: shared state written from MCP output without integrity check | LLM04, ASI06 |
| MCP-008 | High | MCP stdio transport command loaded from variable path | LLM03, ASI04 |
| MCP-009 | High | MCP session ID used as auth decision without expiry check | ASI03 |
| MCP-010 | Critical | MCP transport event payload injected into LLM context without sanitisation | LLM01, ASI01 |
| MCP-011 | Critical | MCP tool description contains prompt injection instruction verbs | LLM01, ASI01 |
| MCP-012 | High | MCP tool name contains prompt control keywords or suspicious characters | LLM01, ASI02 |

### Supply chain (SCH)

Unsafe model deserialisation and tooling that strips model safety training.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| SCH-001 | Critical | Unsafe pickle or torch deserialization: arbitrary code execution risk | LLM03, ASI05 |
| SCH-003 | Critical | LangChain unsafe deserialization without object allowlist (CVE-2025-68664) | LLM03, ASI05 |
| SCH-004 | Critical | Model safety ablation package in dependency list | LLM03, LLM04 |
| SCH-005 | Critical | Model refusal removal script detected | LLM03, LLM04 |
| SCH-006 | Critical | Package manager install of model safety bypass tooling | LLM03, LLM04 |

### Resource consumption (DOS)

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| DOS-001 | Medium | Unbounded LLM completion: reasoning-inflation / ThinkTrap risk | LLM10 |

### Persistence and concealment (PST)

Host persistence and anti-forensics patterns in agent tooling, skills and scripts.

| ID | Severity | Rule | OWASP |
|----|----------|------|-------|
| PST-001 | Critical | Cron job persistence: crontab edit or write to cron path | LLM06, ASI10 |
| PST-002 | Critical | Systemd service persistence: systemctl enable or write to systemd path | LLM06, ASI10 |
| PST-003 | High | macOS LaunchDaemon or LaunchAgent persistence | LLM06, ASI10 |
| PST-004 | High | Shell profile modification: write to .bashrc, .zshrc, or /etc/profile | LLM06, ASI10 |
| PST-005 | High | Audit evasion: shell history cleared or disabled | ASI10 |
| PST-006 | High | Log tampering: truncate or shred on /var/log paths | ASI10 |
| PST-007 | High | Sensitive command output suppressed to /dev/null | ASI10 |
| PST-008 | Medium | Detached process spawning: nohup, setsid, screen, or tmux backgrounding | LLM06, ASI10 |

<!-- rules:end -->

---

## Example Output

```
=== ContextHound Scan ===

src/prompts/assistant.ts (file score: 45)
  [HIGH] INJ-001: Direct user input concatenation without delimiter
    File: src/prompts/assistant.ts:7
    Evidence: Answer the user's question: ${userInput}`;
    Confidence: medium
    MITRE:      T1190
    OWASP:      LLM01
    Risk points: 23
    Remediation: Wrap user input with clear delimiters (e.g., triple backticks) and label it as "untrusted user content".

  [HIGH] EXF-001: Prompt references secrets, API keys, or credentials
    File: src/prompts/assistant.ts:6
    Evidence: The database password is: secret123.
    Confidence: medium
    MITRE:      T1552
    OWASP:      LLM02
    Risk points: 23
    Remediation: Remove all secret values from prompts. Use environment variables server-side; never embed credentials in prompt text.

────────────────────────────────────────────────────────────
Repo Risk Score: 45/100 (MEDIUM)
Threshold: 60
Total findings: 3
By severity: high: 2  medium: 1

✓ PASSED: score 45 is below the threshold of 60.
```

This is `hound scan --verbose` with one finding left out; without `--verbose` each finding is a single line.

---

## Project Structure

```
src/
├── cli.ts                  # CLI entry point (Commander.js)
├── index.ts                # Library entry point (require('context-hound'))
├── fix.ts                  # hound fix: safe automatic fixes
├── version.ts              # Version read from package.json
├── types.ts                # Shared TypeScript types
├── config/
│   ├── defaults.ts         # Default include/exclude globs and settings
│   ├── loader.ts           # Config discovery, extends, env var overrides, option parsing
│   ├── schema.ts           # Config spec: validator and JSON Schema generator
│   └── presets.ts          # Rule presets (--preset)
├── scanner/
│   ├── discover.ts         # File discovery, .gitignore and .houndignore
│   ├── extractor.ts        # Prompt extraction (raw, code, structured)
│   ├── languages.ts        # LLM API trigger patterns per language extension
│   ├── cache.ts            # Incremental scan cache (.hound-cache.json)
│   ├── suppressions.ts     # Inline hound-disable directives
│   ├── gitDiff.ts          # Changed files for --diff (merge base)
│   ├── paths.ts            # Portable, repository-relative report paths
│   ├── fingerprint.ts      # Stable finding fingerprints
│   ├── baseline.ts         # Baseline comparison (--baseline)
│   └── pipeline.ts         # Orchestrates the scan: discovery, cache, rules, plugins
├── rules/
│   ├── types.ts            # Rule interface and scoring helpers
│   ├── index.ts            # Rule registry
│   ├── owasp.ts            # OWASP LLM and Agentic Top 10 mapping
│   ├── mitigation.ts       # Mitigation presence detection
│   ├── taint.ts            # INJ-015 taint analysis
│   └── *.ts                # One file per rule family (injection.ts, mcp.ts, persistence.ts, ...)
├── runtime/                # createGuard(): inspection of live message arrays
├── scoring/                # Risk score, gates and rule filtering
└── report/                 # console, json, jsonl, sarif, githubAnnotations, markdown,
                            # html, csv, junit, prComment and sanitize (escaping)
schema/                     # JSON Schema for the config file (npm run schema)
scripts/                    # Benchmark, schema and README generators, Action helpers
benchmarks/                 # Labelled safe and unsafe corpus (npm run benchmark)
attacks/                    # Example injection strings (not executed against models)
tests/                      # Jest suites and fixtures
action.yml                  # Composite GitHub Action (uses: IulianVOStrut/ContextHound@v2)
```

---

## Benchmark

ContextHound ships a labeled benchmark dataset for measuring false-positive and detection rates. Run it after building:

```bash
npm run benchmark
```

The benchmark scans two fixture directories:

| Directory | Purpose |
|-----------|---------|
| `benchmarks/safe/` | 19 realistic benign files: README, changelog and security docs, a news dataset, a system prompt that quotes attacks in order to refuse them, standard chat and RAG code with delimiters, Python logging, PyTorch `model.eval()`, configs. Expect **0** findings |
| `benchmarks/unsafe/` | 15 files with real vulnerabilities, each labelled with the rule that must fire |

**Results on 2.2.1:**

```
File-level FP rate:   0.0%   (0 / 19 safe files produced findings)
Detection rate:      100.0%  (15/15 expected findings triggered)
```

On the same corpus, the rules as they were before 2.1.0 produced findings in 10 of the 19 safe files (52.6%). As a real-world check, scanning [MetaGPT](https://github.com/geekan/MetaGPT) with default settings went from 192 findings (score 100) to 17 (score 70), most of them unsafe deserialisation, `shell=True` with a variable, and agent prompts.

The benchmark exits with code 1 if any false positives or false negatives are found, making it suitable as a CI quality gate for rule changes. To add a fixture, drop a file into `benchmarks/safe/` or `benchmarks/unsafe/` and update `benchmarks/labels.json` with the expected findings.

### Per-rule precision / recall

The benchmark also prints a **per-rule signal table** (worst F1 first) so low-precision rules are easy to spot: true and false positives, false negatives, precision, recall, and F1 for every labelled rule. FP counts come from the `safe/` fixtures (ground truth: zero findings); TP/FN come from the labelled `unsafe/` fixtures. Pass `--report <path>` to also emit a machine-readable JSON report for dashboards or CI trend tracking:

```bash
npm run benchmark -- --report bench-report.json
```

---

## Browser Extension

The ContextHound browser extension brings real-time prompt injection detection to Chrome and Firefox. It uses the same rule engine as the CLI, compiled and bundled locally, with no network requests and no backend.

> **Status:** the Firefox extension is live ([install from Firefox Add-ons](https://addons.mozilla.org/firefox/addon/contexthound/)). Chrome submission is awaiting Web Store review. Source available at [github.com/IulianVOStrut/ContextHound-Extensions](https://github.com/IulianVOStrut/ContextHound-Extensions).

### Features

**Scan pill**
A lightweight indicator appears next to any AI chat input on any website. As you type, the extension scans the text with the ContextHound rule engine and shows a risk score and findings in a dropdown panel, without leaving the page.

**DevTools panel**
Open browser DevTools and select the ContextHound tab to monitor live LLM API traffic. The extension intercepts outbound requests to OpenAI, Anthropic, Google Gemini, Mistral, Groq, Cohere, DeepSeek, and other services, scanning both the request body and response for injection content. A toolbar badge reflects the highest risk score seen in the current session.

**Popup scanner**
Click the toolbar icon to paste and scan any text manually. Useful for reviewing a prompt or system instruction received from a third party before using it.

### How the browser extension captures request bodies

Chrome and Firefox's DevTools HAR API (`onRequestFinished`) does not reliably include request body bytes for streaming/SSE responses, which most AI chat services use. The extension solves this with a two-layer approach:

1. `chrome.webRequest.onBeforeRequest` intercepts raw request bytes in the service worker before the request is sent, caches them briefly in `chrome.storage.session` (TTL: 5 minutes).
2. When `onRequestFinished` fires and `postData` is absent, the DevTools page fetches the cached body from the service worker via a `POP_BODY_CACHE` message.

### Privacy

The extension collects no user data. All scanning is local. See the [privacy policy](https://contexthound.com/privacy).

---

## Limitations

- Rules use regex and structural heuristics, not full semantic analysis. False positives are possible; always review findings in context.
- Prompts are not executed against a model; this is purely static analysis.
- Extraction uses pattern matching rather than a full AST. Complex dynamic prompt construction may be missed.
- For non-JS/TS languages (Python, Go, Rust, etc.) a file is analysed only when an LLM library import is detected. Files that construct prompts without a recognised import will not be extracted.

---

## Contributing

Contributions are welcome. To add a new rule:

1. Add it to the appropriate file in `src/rules/` (or create a new one for a new family)
2. Register it in `src/rules/index.ts` and map it to OWASP categories in `src/rules/owasp.ts`
3. Add at least one positive and one negative test case in `tests/rules.test.ts`, and a labelled fixture in `benchmarks/unsafe/`
4. Run `npm run docs` to regenerate the rule tables in this README
5. Run `npm run lint`, `npm test` and `npm run benchmark`

---

## License

MIT
