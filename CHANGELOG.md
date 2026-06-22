# Changelog

All notable changes to ContextHound are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

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
