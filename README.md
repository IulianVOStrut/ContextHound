# ContextHound

> Static analysis tool that scans your codebase for LLM prompt-injection and multimodal security vulnerabilities. Runs offline, no API calls required.

[![CI](https://github.com/IulianVOStrut/ContextHound/actions/workflows/context-hound.yml/badge.svg)](https://github.com/IulianVOStrut/ContextHound/actions/workflows/context-hound.yml)
[![npm](https://img.shields.io/npm/v/context-hound)](https://www.npmjs.com/package/context-hound)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
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

It fits into your existing workflow as a CLI command, an `npm` script, or a GitHub Action, with zero external dependencies.

---

## Features

| | |
|---|---|
| **95 security rules** | Across 14 categories: injection, exfiltration, jailbreak, unsafe tool use, command injection, RAG poisoning, encoding, output handling, multimodal, skills marketplace, agentic, MCP, supply chain, DoS |
| **Numeric risk score (0-100)** | Normalized repo-level score with low, medium, high and critical thresholds |
| **Mitigation detection** | Explicit safety language in your prompts reduces your score |
| **7 output formats** | Console, JSON, SARIF, GitHub Annotations, Markdown, JSONL streaming, and interactive HTML |
| **GitHub Action included** | Fails CI on high risk and uploads SARIF results automatically |
| **Multi-language scanning** | Detects LLM API usage in Python, Go, Rust, Java, C#, PHP, Ruby, Swift, Kotlin, Vue, Bash — not just TypeScript/JavaScript |
| **Rule filtering** | `excludeRules`/`includeRules` with prefix-glob syntax (`CMD-*`); `minConfidence` filter |
| **Incremental cache** | `.hound-cache.json` skips unchanged files on re-runs; `--no-cache` to disable |
| **Plugin system** | Load custom rules from local `.js` files via `"plugins": ["./my-rule.js"]` in config |
| **Baseline / diff mode** | `--baseline results.json` — only report and fail on findings not present in a prior scan |
| **Watch mode** | `--watch` re-scans on file changes and shows delta findings |
| **Parallel scanning** | Concurrent file processing (`--concurrency <n>`, default 8) |
| **Fully offline** | No API calls, no telemetry, no paid dependencies |

---

## Installation

**Global install** — adds the `hound` command to your PATH:

```bash
npm install -g context-hound
```

**Per-project install** — scoped to one repo, runs via `npx hound` or an npm script:

```bash
npm install --save-dev context-hound
```

**Zero-install** — no install needed, uses the cached npm registry copy:

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

# List all 95 rules
hound scan --list-rules

# Interactive HTML report (self-contained, open in browser)
hound scan --format html --out report

# Re-scan on file changes
hound scan --watch

# Parallel scanning (default is 8; tune for your machine)
hound scan --concurrency 16

# Disable incremental cache for a clean run
hound scan --no-cache

# Baseline mode — only report findings new since the last saved scan
hound scan --format json --out baseline          # save a baseline
hound scan --baseline baseline.json             # compare future scans against it

# Load a custom rule from a local plugin file
hound scan  # plugin declared in .contexthoundrc.json "plugins" field

# Only run high-confidence rules
hound scan --config .contexthoundrc.json  # set minConfidence: "high"

# Fail if any single file scores >= 40
hound scan --fail-file-threshold 40
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Passed — score below threshold, no `failOn` violation |
| `1` | Unhandled error or bad arguments |
| `2` | Threshold breached — repo score ≥ threshold, or file threshold exceeded |
| `3` | `--fail-on` violation — finding of the specified severity found |

---

## GitHub Actions

Add to your workflow to block merges when prompt risk is too high:

```yaml
# .github/workflows/context-hound.yml
name: Prompt Audit

on: [push, pull_request]

jobs:
  hound:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm install -g context-hound

      - run: hound scan --format console,sarif,github-annotations --out results.sarif

      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Findings will appear in your repository's **Security > Code scanning** tab. The `github-annotations` format posts inline PR comments and writes a summary table to the GitHub step summary.

---

## Configuration

Run `hound init` to scaffold a `.contexthoundrc.json`, or create one manually:

```json
{
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
| `include` | `**/*.{ts,tsx,js,jsx,py,go,rs,java,kt,cs,php,rb,swift,vue,sh,bash,hs,md,txt,yaml,yml,json}` | Glob patterns to scan |
| `exclude` | `**/node_modules/**`, `**/dist/**`, etc. | Glob patterns to ignore |
| `threshold` | `60` | Fail if repo score is at or above this value (exit code 2) |
| `formats` | `["console"]` | Output formats: `console`, `json`, `sarif`, `github-annotations`, `markdown`, `jsonl`, `html` |
| `out` | auto | Base path for file output |
| `verbose` | `false` | Show remediations and confidence per finding |
| `failOn` | unset | Exit code 3 on first finding of: `critical`, `high`, or `medium` |
| `maxFindings` | unset | Stop after N findings |
| `excludeRules` | `[]` | Rule IDs or prefix globs to skip (e.g. `"CMD-*"`, `"JBK-002"`) |
| `includeRules` | `[]` | Run only these rule IDs (empty = run all) |
| `minConfidence` | unset | Skip rules below this confidence: `low`, `medium`, or `high` |
| `failFileThreshold` | unset | Fail (exit code 2) if any single file scores at or above this value |
| `concurrency` | `8` | Max files processed in parallel |
| `cache` | `true` | Enable incremental scan cache (`.hound-cache.json`); set `false` or use `--no-cache` to disable |
| `plugins` | `[]` | Paths to local `.js` rule plugins; each must export a `Rule` or `Rule[]` |
| `baseline` | unset | Path to a previous JSON report; only findings absent from the baseline are reported |

### Environment variable overrides

All key settings can be overridden at runtime without editing the config file:

| Variable | Overrides |
|----------|-----------|
| `HOUND_THRESHOLD` | `threshold` |
| `HOUND_FAIL_ON` | `failOn` |
| `HOUND_MIN_CONFIDENCE` | `minConfidence` |
| `HOUND_VERBOSE` | `verbose` (truthy: `1`, `true`, `yes`) |
| `HOUND_CONFIG` | path to config file |

### `.houndignore`

Place a `.houndignore` file in your project root to add exclusion patterns without editing `.contexthoundrc.json`. Follows the same glob syntax; lines starting with `#` are comments.

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

Plugin rules are subject to the same `excludeRules`, `includeRules`, and `minConfidence` filters as built-in rules.

### Baseline / diff mode

Save a baseline after an initial scan, then only report findings that are new in subsequent scans:

```bash
# Save baseline
hound scan --format json --out baseline

# Future scans only report new issues
hound scan --baseline baseline.json
```

Findings are matched by `ruleId + file` — line shifts don't cause false new-finding alerts.

---

## Risk Scoring

Each finding carries **risk points** calculated as:

```
risk_points = severity_weight × confidence_multiplier
```

Points are totalled, capped at 100, and classified:

| Score | Level | Suggested action |
|-------|-------|-----------------|
| 0-29 | 🟢 Low | No action required |
| 30-59 | 🟡 Medium | Review before merging |
| 60-79 | 🟠 High | Fix before merging |
| 80-100 | 🔴 Critical | Block deployment |

If your prompts include explicit safety language (input delimiters, refusal-to-reveal instructions, tool allowlists), risk points for that prompt are reduced proportionally.

---

## Rules

### A. Injection (INJ)

| ID | Severity | Description |
|----|----------|-------------|
| INJ-001 | High | Direct user input concatenated into prompt without delimiter |
| INJ-002 | Medium | Missing "treat user content as data" boundary language |
| INJ-003 | High | RAG/retrieved context included without untrusted separator |
| INJ-004 | High | Tool-use instructions overridable by user content |
| INJ-005 | High | Serialised user object (`JSON.stringify`) interpolated directly into a prompt template |
| INJ-006 | Medium | HTML comment containing hidden instruction verbs in user-controlled content |
| INJ-007 | Medium | User input wrapped in code-fence delimiters without stripping backticks first |
| INJ-008 | High | HTTP request data (`req.body`, `req.query`, `req.params`) interpolated into `role: "system"` template string |
| INJ-009 | Critical | HTTP request body parsed as the messages array directly — attacker controls role and content |
| INJ-010 | High | Plaintext role-label transcript (`User:`, `Assistant:`, `system:`) built with untrusted input concatenation |
| INJ-011 | High | Browser DOM or URL source (`window.location`, `document.cookie`, `getElementById`) fed directly into LLM call |

### B. Exfiltration (EXF)

| ID | Severity | Description |
|----|----------|-------------|
| EXF-001 | Critical | Prompt references secrets, API keys, or credentials |
| EXF-002 | Critical | Prompt instructs model to reveal system prompt or hidden instructions |
| EXF-003 | High | Prompt indicates access to confidential or private data |
| EXF-004 | High | Prompt includes internal URLs or infrastructure hostnames |
| EXF-005 | High | Sensitive variable (token, password, key) encoded as Base64 in output |
| EXF-006 | High | Full prompt or message array logged via `console.log` / `logger.*` without redaction |
| EXF-007 | Critical | Actual secret value embedded in prompt alongside a "never reveal" instruction |

### C. Jailbreak (JBK)

| ID | Severity | Description |
|----|----------|-------------|
| JBK-001 | Critical | Known jailbreak phrase detected ("ignore instructions", "DAN", etc.) |
| JBK-002 | High | Weak safety wording ("always comply", "no matter what") |
| JBK-003 | High | Role-play escape hatch that undermines safety constraints |
| JBK-004 | High | Agent instructed to act without confirmation or human review ("proceed automatically", "no confirmation needed") |
| JBK-005 | High | Evidence-erasure or cover-tracks instruction ("delete logs", "leave no trace") |
| JBK-006 | High | Policy-legitimacy framing combined with an unsafe action request ("as a penetration tester, escalate privileges") |
| JBK-007 | High | Model identity spoofing — claims to be a different AI model combined with a safety-bypass directive |
| JBK-008 | High | Prompt compression attack — instruction to compress or summarise the system prompt |
| JBK-009 | High | Nested instruction injection — imperative commands wrapped in a "safe/harmless summary/translation" framing |

### D. Unsafe Tool Use (TOOL)

| ID | Severity | Description |
|----|----------|-------------|
| TOOL-001 | Critical | Unbounded tool execution ("run any command", "browse anywhere", backtick shell substitution) |
| TOOL-002 | Medium | Tool use described with no allowlist or usage policy |
| TOOL-003 | High | Code execution mentioned without sandboxing constraints |
| TOOL-004 | Critical | Tool description or schema field sourced from a user-controlled variable |
| TOOL-005 | Critical | Tool `name` or endpoint `url` sourced from user-controlled input (`req.body`, `req.query`, etc.) |

### E. Command Injection (CMD)

Detects vulnerable patterns in the code surrounding AI tools, where a successful prompt injection can escalate into full command execution. Informed by real CVEs found in Google's Gemini CLI by Cyera Research Labs (2025).

| ID | Severity | Description |
|----|----------|-------------|
| CMD-001 | Critical | Shell command built with unsanitised variable interpolation — JS/TS (`execSync(\`cmd ${var}\``), Python (`subprocess.run(f"cmd {var}")`), PHP (`shell_exec($var)`), Go (`exec.Command` + `fmt.Sprintf`), Rust (`Command::new` + `format!`) |
| CMD-002 | High | Incomplete command substitution filtering: blocks `$()` but not backticks, or vice versa |
| CMD-003 | High | File path from `glob.sync` or `readdirSync` used directly in a shell command without sanitisation |
| CMD-004 | Critical | Python `subprocess.run`/`subprocess.call` invoked with `shell=True` and a variable or f-string command argument |
| CMD-005 | Critical | PHP `shell_exec`, `system`, `passthru`, `exec`, or `popen` called with a `$variable` argument |

### F. RAG Poisoning (RAG)

Detects architectural mistakes in Retrieval-Augmented Generation pipelines that allow retrieved or ingested content to override system-level instructions.

| ID | Severity | Description |
|----|----------|-------------|
| RAG-001 | High | Retrieved or external content assigned to `role: "system"` in a messages array |
| RAG-002 | High | Instruction-like phrases ("system prompt:", "always return", "never redact") detected inside a document ingestion loop |
| RAG-003 | High | Agent memory store written directly from user-controlled input without validation |
| RAG-004 | Medium | Prompt instructs model to treat retrieved context as highest priority, overriding developer instructions |
| RAG-005 | Medium | Provenance-free retrieval — chunks inserted into prompt without source metadata check |
| RAG-006 | High | No ACL or trust-tier filter applied before retrieval enters the prompt |

### G. Encoding (ENC)

Detects encoding-based injection and evasion techniques where Base64 or similar encodings are used to smuggle instructions past string-based filters.

| ID | Severity | Description |
|----|----------|-------------|
| ENC-001 | Medium | `atob`, `btoa`, or `Buffer.from(x, 'base64')` called on a user-controlled variable near prompt construction |
| ENC-002 | High | Hidden Unicode control characters (zero-width spaces, bidi overrides) detected near instruction keywords |

### H. Output Handling (OUT)

Covers the output side of the LLM pipeline — how your application consumes model responses. Unsafe consumption can turn a prompt-injection payload into an application-level exploit.

| ID | Severity | Description |
|----|----------|-------------|
| OUT-001 | Critical | `JSON.parse()` (JS/TS) or `json.loads()` (Python) called on LLM output without schema validation (Zod, AJV, Joi, Pydantic, Marshmallow, etc.) |
| OUT-002 | Critical | LLM-generated Markdown or HTML rendered without DOMPurify or equivalent sanitizer |
| OUT-003 | Critical | LLM output used directly as argument to `exec()`, `eval()`, or `db.query()` |
| OUT-004 | Critical | Python `eval()` or `exec()` called with LLM-generated output as the argument |

### I. Multimodal (VIS)

Covers trust-boundary violations specific to vision, audio/video, and OCR pipelines. Multimodal inputs are an emerging injection vector: an attacker who controls an image URL, an audio file, or a scanned document can use these rules' patterns to smuggle instructions into the model.

| ID | Severity | Description |
|----|----------|-------------|
| VIS-001 | Critical | User-supplied image URL or base64 data forwarded to a vision API (gpt-4o, Claude 3, Gemini Vision) without domain or MIME validation |
| VIS-002 | Critical | `fs.readFile`/`readFileSync` called with a user-controlled path in a file that also builds a vision API message — path traversal into multimodal input |
| VIS-003 | High | Audio/video transcription output (Whisper, AssemblyAI, Deepgram, etc.) fed directly into prompt messages without sanitization — RAG poisoning via audio source |
| VIS-004 | High | OCR output (Tesseract, Google Vision) interpolated into a `role: "system"` message or system prompt variable |

### J. Skills Marketplace (SKL) — v1.1

Targets OpenClaw `SKILL.md` files and any markdown files inside `skills/` directories. Fires on self-authoring attacks, remote skill loading, injected instructions, unsafe command dispatch, sensitive path access, privilege escalation claims, and hardcoded credentials in YAML frontmatter.

| ID | Severity | Description |
|----|----------|-------------|
| SKL-001 | Critical | Skill body instructs agent to write or modify other skill files — self-authoring attack that persists across agent restarts |
| SKL-002 | Critical | Skill body instructs agent to fetch or load skills from an external URL — allows attacker to change skill behavior after installation |
| SKL-003 | Critical | Skill body contains prompt injection phrases targeting agent core instructions (`ignore previous instructions`, `you are now unrestricted`, etc.) |
| SKL-004 | High | Skill frontmatter uses `command-dispatch: tool` with `command-arg-mode: raw` — forwards raw user input to a tool, bypassing model safety reasoning |
| SKL-005 | High | Skill body references sensitive filesystem paths (`~/.ssh`, `~/.env`, `/etc/passwd`, `../../`) for agent to read and potentially exfiltrate |
| SKL-006 | High | Skill body claims elevated privileges or instructs agent to override or disable other installed skills |
| SKL-007 | Critical | Hardcoded credential value (API key, token, password) found in YAML frontmatter — exposed to anyone who receives or installs the skill |
| SKL-008 | Critical | Heartbeat C2 — skill schedules periodic remote fetch to silently overwrite its own instructions after a clean install |
| SKL-009 | Critical | Agent identity denial — skill instructs agent to deny being AI, claim to be human, or adopt a deceptive persona |
| SKL-010 | Critical | Anti-scanner evasion — skill contains text explicitly designed to mislead security auditing tools |
| SKL-011 | Critical | SOUL.md / IDENTITY.md persistence — skill writes instructions to agent identity files that survive uninstallation |
| SKL-012 | High | Self-propagating worm — skill instructs agent to spread via SSH or `curl\|bash` to reachable hosts |
| SKL-013 | High | Autonomous financial transactions — skill executes crypto transactions or holds private keys without per-transaction user confirmation |

> **Scanning OpenClaw skills:** Run `npx hound scan --dir ./skills` or add `**/skills/**/*.md` and `**/SKILL.md` to your `include` config. ContextHound automatically emits skill files as `code-block` for multi-line rule analysis.

### K. Agentic (AGT) — v1.3 / v1.9

Targets risks specific to multi-step agentic systems: unbounded execution loops, unvalidated memory writes, user input leaking into agent planning, inter-agent trust boundary violations, and OWASP Agentic AI Security Issues (ASI) gaps.

| ID | Severity | Description |
|----|----------|-------------|
| AGT-001 | Critical | Tool call parameter receives system-prompt content — `tool_call`/`function_call` argument value containing `system:` or `instructions:` field contents |
| AGT-002 | High | Agent loop with no iteration or timeout guard — no `max_iterations`, `max_steps`, `max_turns`, `timeout`, or `recursion_limit` in agent config or code |
| AGT-003 | High | Agent memory written from unvalidated LLM output — `memory.save()`, `memory.add()`, or `vectorstore.upsert()` called with a raw model response variable |
| AGT-004 | High | Plan injection — user input interpolated directly into agent planning, task, or goal prompt without a trust-boundary wrapper |
| AGT-005 | Critical | Agent trusts claimed identity without cryptographic verification — trust decision based on `agentId`, `sender`, `source`, or `from_agent` field without HMAC, JWT, or shared-secret verification |
| AGT-006 | High | Raw agent output chained as input to another agent without validation — `.run()`, `.invoke()`, or `.generate()` called with another agent's `.output`/`.content`/`.result` directly as the argument |
| AGT-007 | Critical | Agent self-modification — agent rewrites its own `system_prompt`, `instructions`, or `tools` list with LLM-generated content at runtime |
| AGT-008 | Critical | ASI03 — Agent calls `assumeRole`, `grantAccess`, or `setPermissions` with a value derived from LLM output; privilege escalation via prompt injection |
| AGT-009 | High | ASI04 — Agent loads a tool or plugin at runtime from a variable path or dynamic import, enabling supply chain substitution |
| AGT-010 | High | ASI07 — Raw agent output forwarded to another agent via `send`/`route`/`dispatch` without HMAC, JWT signing, or schema validation |
| AGT-011 | High | ASI08 — Agent plan step error caught silently (no rethrow, no error-state flag); downstream steps proceed on bad or incomplete state |

### L. MCP Security (MCP) — v1.7 / v1.8

Covers trust-boundary and supply-chain risks specific to the Model Context Protocol. MCP introduces a new attack surface: tool descriptions, transport URLs, event payloads, and cross-server shared state can all carry injection or privilege-escalation payloads.

| ID | Severity | Description |
|----|----------|-------------|
| MCP-001 | Critical | MCP tool description injected into LLM prompt without sanitization — raw `tool.description` value used in `role: "system"` or `messages.push()` |
| MCP-002 | High | MCP tool registered with dynamic name or description — `server.tool()` first argument is a variable or template literal, enabling rug-pull attacks post-approval |
| MCP-003 | High | MCP sampling/createMessage handler without human approval guard — `setRequestHandler(CreateMessageRequestSchema)` without `requireHumanApproval`, `confirm`, or `approve` check |
| MCP-004 | Medium | MCP transport URL constructed from variable — `SSEClientTransport` or `WebSocketClientTransport` initialised with a `new URL(variable)` instead of a static string |
| MCP-005 | High | MCP stdio transport uses `shell: true` — makes the command string shell-interpolated and injectable if any argument is user-controlled |
| MCP-006 | Critical | MCP confused deputy — auth token from MCP request forwarded to downstream API without re-validation; `Authorization` header value sourced directly from `request.params`, `context`, or `event` |
| MCP-007 | High | Cross-MCP context poisoning — shared/global context store written from MCP output without hash, signature, or provenance check |
| MCP-008 | High | MCP stdio transport command loaded from variable path — `StdioClientTransport`/`StdioServerTransport` `command:` field is a variable rather than a static string literal |
| MCP-009 | High | MCP session ID used as auth decision without expiry check — `sessionId`/`connectionId` equality comparison with no TTL, `expiresAt`, or `isExpired` guard (replay attack) |
| MCP-010 | Critical | MCP transport event payload injected into LLM context without sanitisation — event/message `.data`, `.content`, or `.payload` used directly in `messages.push()` or a `content:` field |

---

## Example Output

```
=== ContextHound Prompt Audit ===

src/prompts/assistant.ts (file score: 73)
  [HIGH] INJ-001: Direct user input concatenation without delimiter
    File: src/prompts/assistant.ts:12
    Evidence: Answer the user's question: ${userInput}
    Confidence: medium
    Risk points: 23
    Remediation: Wrap user input with clear delimiters (e.g., triple backticks)
                 and label it as "untrusted user content".

  [CRITICAL] EXF-001: Prompt references secrets, API keys, or credentials
    File: src/prompts/assistant.ts:8
    Evidence: The database password is: secret123.
    Confidence: high
    Risk points: 50
    Remediation: Remove all secret values from prompts. Use environment
                 variables server-side; never embed credentials in prompt text.

────────────────────────────────────────────────────────
Repo Risk Score: 87/100 (CRITICAL)
Threshold: 60
Total findings: 5
By severity: critical: 2  high: 2  medium: 1

✗ FAILED - score meets or exceeds threshold.
```

---

## Project Structure

```
src/
├── cli.ts                  # CLI entry point (Commander.js)
├── types.ts                # Shared TypeScript types
├── config/
│   ├── defaults.ts         # Default include/exclude globs and settings
│   └── loader.ts           # .contexthoundrc.json loader + env var overrides
├── scanner/
│   ├── discover.ts         # File discovery via fast-glob
│   ├── extractor.ts        # Prompt extraction (raw, code, structured)
│   ├── languages.ts        # LLM API trigger patterns per language extension
│   ├── cache.ts            # Incremental scan cache (.hound-cache.json)
│   └── pipeline.ts         # Orchestrates the full scan; parallel + cache + plugins
├── rules/
│   ├── types.ts            # Rule interface and scoring helpers
│   ├── injection.ts        # INJ-* rules
│   ├── exfiltration.ts     # EXF-* rules
│   ├── jailbreak.ts        # JBK-* rules
│   ├── unsafeTools.ts      # TOOL-* rules
│   ├── commandInjection.ts # CMD-* rules
│   ├── rag.ts              # RAG-* rules
│   ├── encoding.ts         # ENC-* rules
│   ├── outputHandling.ts   # OUT-* rules
│   ├── multimodal.ts       # VIS-* rules
│   ├── skills.ts           # SKL-* rules
│   ├── agentic.ts          # AGT-* rules
│   ├── mcp.ts              # MCP-* rules
│   ├── supplyChain.ts      # SCH-* rules
│   ├── dos.ts              # DOS-* rules
│   ├── mitigation.ts       # Mitigation presence detection
│   └── index.ts            # Rule registry
├── runtime/
│   ├── index.ts            # createGuard() — runtime message inspection API
│   ├── inspect.ts          # Core inspection logic for live message arrays
│   └── types.ts            # RuntimeMessage, InspectResult, GuardConfig types
├── scoring/
│   └── index.ts            # Risk score calculation and rule filtering
└── report/
    ├── console.ts          # ANSI-coloured terminal output
    ├── json.ts             # JSON report builder
    ├── sarif.ts            # SARIF 2.1.0 report builder
    ├── githubAnnotations.ts# GitHub Actions annotation formatter
    ├── markdown.ts         # Markdown report with findings tables
    ├── jsonl.ts            # JSONL streaming formatter
    └── html.ts             # Self-contained interactive HTML report
attacks/                    # Example injection strings (not executed against models)
tests/
├── fixtures/               # Sample prompts for testing
├── rules.test.ts           # Unit tests for all rules
├── scoring.test.ts         # Unit tests for scoring logic
├── scanner.test.ts         # Integration tests for the scan pipeline
├── extractor.test.ts       # Unit tests for prompt extraction
├── formatters.test.ts      # Unit tests for all report formatters
├── mitigation.test.ts      # Unit tests for mitigation detection
└── cli.test.ts             # CLI integration tests (init, list-rules, exit codes)
.github/
├── action.yml              # Reusable composite GitHub Action
└── workflows/
    └── context-hound.yml    # CI workflow
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
| `benchmarks/safe/` | 5 files with genuine safe patterns — expect **0** findings |
| `benchmarks/unsafe/` | 8 files with real vulnerabilities — one rule each |

**Results on v1.4.0:**

```
File-level FP rate:   0.0%   (0 / 5 safe files produced findings)
Detection rate:      100.0%  (8/8 expected findings triggered)
```

The benchmark exits with code 1 if any false positives or false negatives are found, making it suitable as a CI quality gate for rule changes. To add a fixture, drop a file into `benchmarks/safe/` or `benchmarks/unsafe/` and update `benchmarks/labels.json` with the expected findings.

---

## Browser Extension

The ContextHound browser extension brings real-time prompt injection detection to Chrome and Firefox. It uses the same rule engine as the CLI, compiled and bundled locally — no network requests, no backend.

> **Status:** Firefox extension is live — [install from Firefox Add-ons](https://addons.mozilla.org/firefox/addon/contexthound/). Chrome submission is awaiting Web Store review. Source available at [github.com/IulianVOStrut/ContextHound-Extensions](https://github.com/IulianVOStrut/ContextHound-Extensions).

### Features

**Scan pill**
A lightweight indicator appears next to any AI chat input on any website. As you type, the extension scans the text against 70 detection rules and displays a risk score and findings in a dropdown panel — no page navigation required.

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

1. Add it to the appropriate file in `src/rules/` (or create a new one for a new category)
2. Register it in `src/rules/index.ts`
3. Add at least one positive and one negative test case in `tests/rules.test.ts`
4. Run `npm test` to verify all tests pass

---

## License

MIT
