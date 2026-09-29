# Changelog

All notable changes to ContextHound are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Breaking

- **Invalid configuration is an error.** Unknown options, wrong types,
  out-of-range values, invalid JSON, a missing `--config` / `HOUND_CONFIG`
  path and invalid `HOUND_*` values or CLI flags now exit with code 1 instead
  of being silently ignored. Keys starting with `_` remain allowed for comments.
- **Report paths are relative.** Findings, SARIF, annotations and every other
  format use POSIX paths relative to the git repository root (or the scan
  directory outside git) instead of absolute paths.
- **Node.js 20.19 or later** is required (chokidar 5 is ESM-only).
- **Package entry point.** `require('context-hound')` returns the library API
  instead of running the CLI, and the `exports` map limits imports to
  `context-hound`, `context-hound/runtime`, `context-hound/schema.json` and
  `context-hound/package.json`.

### Added

- **Library API** (`src/index.ts`): scanner, config loader, rules, baseline
  helpers and all formatters, with TypeScript types and no import side
  effects.
- **Config JSON Schema** at `schema/contexthoundrc.schema.json`, generated from
  the same spec as the validator and referenced by `$schema` in `hound init`
  output. Typos get a "did you mean" suggestion.
- **Structured failures.** Results and the JSON report include `failures`
  (threshold, file-threshold, fail-on) and the console prints the actual
  reason a scan failed.
- **Finding fingerprints** (rule, path, evidence, occurrence) on every
  finding and as SARIF `partialFingerprints`.

### Fixed

- **`--watch` never reacted to changes**: chokidar 4+ does not expand globs.
  Watch mode now watches the directory, filters events through the normal
  include/exclude rules, handles deletions, honours `--format`, and ignores
  its own report and cache writes.
- **`formats` and `"cache": false` in the config file were ignored.**
- **Default scan scope** now covers every supported language (it skipped
  `.py`, `.go`, `.tsx` and more unless configured) plus `.mts`, `.cts`, `.mjs`
  and `.cjs`, which were misread as raw prompt text. `hound init` writes the
  same defaults. Virtualenv, vendor and build directories and ContextHound's
  own reports are excluded by default, and `--out` paths are never rescanned.
- **Baselines** match on fingerprints, so a new instance of a rule in an
  already-baselined file is reported, and baselines now match across machines.
  Old baselines still load.
- **`--format jsonl --baseline` streamed already-known findings.**
- **Status lines polluted JSONL on stdout**; they go to stderr when stdout
  carries a machine-readable stream.
- **`--diff` compared against the ref tip** and picked up files that only
  changed on the target branch; it now uses the merge base and handles
  unusual file names.
- **`diff` and `reportUnusedSuppressions` in the config file** were never read.
- **Scan cache** prunes entries for files that left the scope, writes compact
  JSON and checks file size as well as mtime.
- **Formatters are side-effect free**: the CLI, not the Markdown and
  annotation builders, appends to the GitHub step summary.

---

## [2.1.0] - 2026-09-29

First npm release since 1.8.0: it also carries everything listed under 2.0.0,
which was never published. Upgrading from 1.8.0 picks up both.

### Added

- **`maxFileSize` option.** Files over 1 MiB are skipped by default
  (`--max-file-size <bytes>`, `0` disables). Skipped files are listed on
  stderr and in the JSON report's `skippedFiles`, so padding a file past the
  limit never hides it silently.
- **Release workflow.** Pushing a `vX.Y.Z` tag runs lint, tests and the
  benchmark, publishes to npm with provenance, creates the GitHub Release and
  moves the `vN` major tag.
- **Rule presets.** `--preset <names>` enables a curated rule bundle
  (`owasp-llm-top10`, `injection`, `jailbreak`, `exfiltration`, `agentic`, `mcp`,
  `supply-chain`, `prompt-files`) instead of listing IDs; presets union with
  `includeRules` and can be combined (`--preset mcp,agentic`). `--list-presets`
  prints them. The composite GitHub Action gains matching `preset` and `diff`
  inputs.
- **pre-commit hook.** A `.pre-commit-hooks.yaml` exposes a `contexthound` hook
  for the [pre-commit](https://pre-commit.com) framework; a `prepare` script
  builds `dist/` on install so the hook works from a git ref.

- **`INJ-015` — lightweight taint analysis (JS/TS).** Follows an *arbitrarily
  named* variable from an unambiguous untrusted source (HTTP request fields, CLI
  args, browser URL/cookie) into a prompt sink — including one-hop aliases —
  catching flows the name-based INJ rules miss. Conservative by design: sanitiser
  wrappers clear taint, only prompt-like template literals are treated as sinks,
  and variable names already covered by `INJ-001` are skipped to avoid
  double-reporting. New `taint` rule module; 121 rules total.
- **Inline suppression comments.** Silence a known false positive in source with
  `hound-disable-line`, `hound-disable-next-line`, or `hound-disable` /
  `hound-enable` block markers — recognised in any file type, optionally scoped
  to specific rule IDs and annotated with a `-- reason`. New
  `--report-unused-suppressions` flag lists directives that match nothing so dead
  suppressions can be pruned. `ScanResult` gains `suppressedCount` and
  `unusedSuppressions`.
- **Per-rule precision/recall in the benchmark.** `npm run benchmark` now prints
  a per-rule signal table (TP/FP/FN, precision, recall, F1; worst F1 first) so
  low-precision rules are easy to spot, and accepts `--report <path>` to emit a
  machine-readable JSON report for CI trend tracking. `computePerRule` is now
  exported and unit-tested.
- **`hound explain <RULE-ID>` command.** Prints a rule's severity, confidence,
  category (with a plain-language description), linked MITRE ATT&CK technique,
  remediation, and the exact suppression directive — no scan required. Accepts a
  family prefix (e.g. `hound explain INJ`) and supports `--format json`.
- **`--diff [ref]` changed-files mode.** Scan only files that changed vs. a git
  ref (default `origin/main`) for fast PR gates — covers committed, staged,
  unstaged, and untracked files, and falls back to a full scan with a warning if
  git/the ref is unavailable. Adds `diff` to `AuditConfig`.
- CLI `--version` now reports the correct package version (was hardcoded to an
  old value).

### Security

- **Stored XSS in the HTML report.** A scanned file containing
  `</script><script>...` executed in the browser of whoever opened the report.
  Finding data is now embedded as escaped, inert JSON, all template values are
  escaped, and a Content Security Policy only allows the report's own script by
  hash.
- **Formula injection in the CSV report (CWE-1236).** Cells starting with
  `=`, `+`, `-`, `@`, TAB or CR are prefixed with a quote so spreadsheet apps do
  not evaluate them.
- **Output injection in other formats.** Markdown evidence and file paths can
  no longer break out of their code spans to inject images or links into PR
  summaries; GitHub annotation values are escaped so a crafted file name cannot
  emit extra workflow commands; console output shows control characters, bidi
  overrides and zero-width characters as visible `<U+XXXX>` markers; JUnit drops
  characters that are illegal in XML.
- **Denial of service from scanned content.** Fuzzing every rule found
  quadratic or worse regexes in INJ-001, INJ-003, INJ-006 (cubic: 67s for 40 KB),
  INJ-010, EXF-004, RAG-007, SKL-002, PST-002, PST-003 and PST-007; all now run
  in linear time. Scanning MetaGPT drops from 62.8s to 2.4s with identical
  findings. A regression suite (`tests/redos.test.ts`) guards against new ones.
- **Scan crash from crafted identifiers.** INJ-001 and INJ-007 built regular
  expressions from variable names in scanned code, so `${foo(}` aborted the
  whole scan. Names are now validated and escaped, and a rule that throws
  (built-in or plugin) is skipped with a warning instead of stopping the scan.
- **`--baseline` disabled severity gating.** With a baseline, `--fail-on` and
  `--fail-file-threshold` were ignored, so a new critical finding passed CI.
  Baseline results now go through the same scoring and gating as a normal scan.
- **GitHub Action hardening.** Inputs are passed through `env` and validated
  instead of being interpolated into the shell script, the exact
  `context-hound` version is installed with `--ignore-scripts`, and third-party
  actions are pinned by commit SHA.
- Resolved all 11 Dependabot advisories (1 critical, high, moderate, low). The
  only advisory affecting a runtime dependency was a `picomatch` ReDoS / glob
  method-injection issue reaching production through `fast-glob` → `micromatch`;
  it is now pinned to a patched release. The remaining advisories were all in
  the dev/test toolchain (`handlebars`, `@babel/core`, `flatted`,
  `brace-expansion`, `js-yaml`, and a second `picomatch` line) and never shipped
  in the published package (`files` is limited to `dist/`). All are pinned to
  patched versions via `overrides`; `npm audit` now reports 0 vulnerabilities
  with the full test suite still green.

### Changed

- **GitHub Action moved to the repository root** (`action.yml`), so
  `uses: IulianVOStrut/ContextHound@v2` works. It no longer runs `npm ci` on
  the caller's repository or calls `npx hound` (which resolves an unrelated npm
  package). New inputs `version`, `dir`, `min-confidence`, `upload-sarif` and
  `node-version`; new outputs `score`, `findings`, `passed` and `sarif-file`.
  `threshold` now defaults to the config file instead of always forcing 60.
- **`INJ-006` only matches verbs inside a single HTML comment.** The old
  pattern could run past the first `-->` and match text outside the comment.
- **`DOS-001` retuned for precision.** It previously fired on *every* completion
  call without a token cap (0% precision in the benchmark — it never matched a
  real issue and flagged 4/5 safe fixtures). It now fires only when a call is
  uncapped **and** shows an output-inflation signal — a reasoning model
  (`o1`/`o3`, `reasoning_effort`, extended thinking) or an inflation instruction
  in the prompt (“think step by step”, “be exhaustive”, “in full detail”, “do
  not stop/summarize”) — i.e. the actual ThinkTrap / reasoning-inflation vector.
- **Mitigations are now scoped to the relevant rule.** Previously the total of
  all detected prompt mitigations was applied as a flat reduction to *every*
  finding, so an unrelated guard (e.g. a tool allowlist) could dampen an
  exfiltration or command-injection finding's score. Each mitigation now
  declares the rule categories it addresses (`appliesTo`), and only matching
  mitigations reduce a given finding's risk. New exported
  `mitigationReductionFor(mitigation, ruleId)`.

### Fixed

- **CLI `--version` and the SARIF driver version** are read from
  `package.json`; they were hard-coded (1.8.0 on npm reports 1.7.0).
- **`INJ-001` checked the wrong location for delimiters** when a file had two
  identical lines: its context window now comes from the matched line itself.
- **Markdown report overwrote the GitHub step summary**; it now appends.

- **`INJ-014` false positive on camelCase identifiers.** Its accessor dot was
  optional, so `content: userContent` matched as `user` + `.content`. The dot
  (or `?.`) is now required, so bare identifiers no longer trip the rule while
  `response.content` / `completion.choices[…]` still do.

- **Incremental cache could serve stale findings.** The cache keyed entries on
  file `mtime` alone behind a hardcoded version, so a rules upgrade (new or
  changed rules) or a findings-affecting config change (`--include-rules`,
  `--exclude-rules`, `--min-confidence`) left unchanged files reporting their
  old results. The cache now stores a signature derived from the effective
  ruleset (rule metadata + `check` source, including plugin rules) and the
  relevant config; any change automatically invalidates the cache. Old-format
  caches are discarded on upgrade.

---

## [2.0.0] — 2026-03-15

### Added — 25 new detection rules (95 → 120 total)

**Injection**
- `INJ-012` Conversation history spread into messages array without sanitisation (`T1190`)
- `INJ-013` Tool/function call result inserted into messages without sanitisation (`T1190`)
- `INJ-014` LLM completion piped as user-role content into a subsequent LLM call (`T1190`)

**Jailbreak**
- `JBK-010` Meta-command activation keyword detected (`T1562`)
- `JBK-011` Instruction dismissal — prior rules framed as obsolete or superseded (`T1562`)
- `JBK-012` Priority downgrade — system instructions demoted below user input (`T1562`)
- `JBK-013` Training or safety constraint explicitly declared void (`T1562`)

**Command Injection**
- `CMD-006` Reverse shell via bash `/dev/tcp` file descriptor redirect (`T1059.004`)
- `CMD-007` Named pipe reverse shell — mkfifo piped to shell or netcat (`T1059.004`)
- `CMD-008` Netcat/ncat with execute flag spawning an interactive shell (`T1059.004`)

**RAG Poisoning**
- `RAG-007` Document metadata field interpolated into prompt without sanitisation (`T1190`)

**Output Handling**
- `OUT-005` LLM output written to shared cache without validation — cache poisoning risk (`T1565`)

**MCP Security**
- `MCP-011` MCP tool description contains prompt injection instruction verbs (`T1190`)
- `MCP-012` MCP tool name contains prompt control keywords or suspicious characters

**Supply Chain**
- `SCH-004` Model safety ablation package in dependency list (`T1195.002`)
- `SCH-005` Model refusal removal script detected (`T1195.002`)
- `SCH-006` Package manager install of model safety bypass tooling (`T1195.002`)

**Persistence (new category)**
- `PST-001` Cron job persistence — crontab edit or write to cron path (`T1053.003`)
- `PST-002` Systemd service persistence — systemctl enable or write to systemd path (`T1543.002`)
- `PST-003` macOS LaunchDaemon or LaunchAgent persistence (`T1543.004`)
- `PST-004` Shell profile modification — write to .bashrc, .zshrc, or /etc/profile (`T1546.004`)
- `PST-005` Audit evasion — shell history cleared or disabled (`T1070.003`)
- `PST-006` Log tampering — truncate or shred on /var/log paths (`T1070.002`)
- `PST-007` Sensitive command output suppressed to /dev/null (`T1070`)
- `PST-008` Detached process spawning — nohup, setsid, screen, or tmux backgrounding (`T1202`)

### Added — MITRE ATT&CK tagging

- New optional `mitre?: string` field on `Rule` and `Finding` interfaces
- 75 of 120 rules annotated with MITRE ATT&CK technique IDs
- SARIF output: `attack:<technique>` tag added to `properties.tags`; `helpUri` links to `attack.mitre.org`
- Console verbose mode: `MITRE:` line printed between Confidence and Risk points
- Markdown report: MITRE column in findings table with linked ATT&CK URL
- CSV report: `mitre_technique` column (10th field)
- HTML report: clickable orange MITRE chip; MITRE ID included in filter search
- JUnit report: `MITRE ATT&CK: <technique>` line in failure body

### Changed

- `Rule` interface: `mitre?: string` field added between `category` and `remediation`
- `Finding` interface: `mitre?: string` field added
- `ruleToFinding()`: propagates `mitre` using spread-conditional
- 15 rule categories (was 14) — `persistence` is new

---

## [1.9.0] — 2026-03-08

### Added

- `AGT-008`–`AGT-011`: OWASP ASI03/04/07/08 agentic security rules
- `MCP-006`–`MCP-010`: confused deputy token forwarding, cross-MCP poisoning, session replay, stdio transport path, event payload injection
- `SCH-003`: LangChain unsafe deserialization (CVE-2025-68664)
- `DOS-001`: unbounded LLM completion — ThinkTrap / reasoning-inflation

---

## [1.8.0] — 2026-03-01

### Added

- `MCP-001`–`MCP-005`: Model Context Protocol security rules
- `PST` category foundation (persistence infrastructure)
- Runtime SDK (`context-hound/runtime`) for programmatic scanning

---

## [1.7.0] — 2026-02-28

### Added

- `AGT-001`–`AGT-007`: agentic pipeline security rules
- Multi-language LLM trigger detection (Python, Go, Rust, Java, C#, Ruby, Swift, Kotlin, Vue, Bash)

---

## [1.6.0] — 2026-02-27

### Added

- `SKL-001`–`SKL-013`: Skills Marketplace (OpenClaw SKILL.md) rules

---

## [1.5.0] — 2026-02-27

### Added

- `VIS-001`–`VIS-004`: multimodal / vision API rules
- `ENC-001`–`ENC-006`: encoding obfuscation rules
- `RAG-001`–`RAG-006`: RAG poisoning rules

---

## [1.0.0] — 2026-02-27

### Added

- Initial release: 48 rules across 8 categories (INJ, EXF, JBK, TOOL, CMD, ENC, OUT, VIS)
- CLI with `scan`, `--format json/sarif/markdown/csv/html/junit/jsonl`, `--out`, `--verbose`
- SARIF 2.1, CSV, HTML self-contained report, JUnit XML formatters
- `.contexthoundrc.json` config (include/exclude globs, threshold, failOn)
- `prepublishOnly` build hook
