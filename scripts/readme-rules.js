#!/usr/bin/env node
// Regenerates the rule tables and rule counts in README.md from the rule
// registry. Run with `npm run docs`; tests fail if the committed README is stale.

const START = '<!-- rules:start -->';
const END = '<!-- rules:end -->';

// Display order, heading and introduction for each rule family. A rule whose
// prefix is missing here is an error, so a new family cannot go undocumented.
const FAMILIES = [
  ['INJ', 'Injection', ''],
  ['EXF', 'Exfiltration', ''],
  ['JBK', 'Jailbreak', ''],
  ['TOOL', 'Unsafe tool use', ''],
  ['CMD', 'Command injection',
    'Vulnerable patterns in the code around AI tools, where a successful prompt injection can escalate into command execution. Informed by the CVEs Cyera Research Labs found in Google\'s Gemini CLI (2025), plus reverse-shell patterns.'],
  ['RAG', 'RAG poisoning',
    'Architectural mistakes in retrieval-augmented generation pipelines that let retrieved or ingested content override system-level instructions.'],
  ['ENC', 'Encoding and hidden content',
    'Encodings and invisible Unicode used to smuggle instructions past string filters and human review. `hound fix` removes the characters flagged by ENC-002 to ENC-005.'],
  ['OUT', 'Output handling',
    'How the application consumes model responses. Unsafe consumption turns a prompt-injection payload into an application-level exploit.'],
  ['VIS', 'Multimodal',
    'Trust-boundary violations in vision, audio and OCR pipelines, where an attacker who controls an image, a recording or a scanned document can smuggle instructions into the model.'],
  ['SKL', 'Agent skills',
    'Targets `SKILL.md` files and Markdown files inside `skills/` directories: self-authoring, remote skill loading, injected instructions, unsafe command dispatch, sensitive paths, privilege claims and hardcoded credentials in frontmatter.'],
  ['AGT', 'Agentic',
    'Risks specific to multi-step agents: unbounded loops, unvalidated memory writes, user input in planning prompts and inter-agent trust boundaries.'],
  ['MCP', 'Model Context Protocol',
    'Trust-boundary and supply-chain risks in MCP clients and servers: tool descriptions, transport URLs, event payloads and cross-server shared state can all carry injection or privilege-escalation payloads.'],
  ['SCH', 'Supply chain',
    'Unsafe model deserialisation and tooling that strips model safety training.'],
  ['DOS', 'Resource consumption', ''],
  ['PST', 'Persistence and concealment',
    'Host persistence and anti-forensics patterns in agent tooling, skills and scripts.'],
];

const SEVERITY = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

function cell(text) {
  return String(text).replace(/\|/g, '\\|');
}

function idOrder(a, b) {
  return a.id.localeCompare(b.id, 'en', { numeric: true });
}

/** Group rules by ID prefix, in FAMILIES order. Throws on an unknown prefix. */
function groupRules(rules) {
  const known = new Map(FAMILIES.map(([prefix]) => [prefix, []]));
  for (const rule of rules) {
    const prefix = rule.id.split('-')[0];
    const list = known.get(prefix);
    if (!list) throw new Error(`No README family for rule prefix ${prefix} (${rule.id}); add it to scripts/readme-rules.js`);
    list.push(rule);
  }
  return FAMILIES
    .map(([prefix, name, intro]) => ({ prefix, name, intro, rules: known.get(prefix).sort(idOrder) }))
    .filter(f => f.rules.length > 0);
}

/** The Markdown between the rules markers. */
function renderRules(rules) {
  const families = groupRules(rules);
  const out = [
    START,
    `<!-- Generated from the rule registry by \`npm run docs\`. Do not edit by hand. -->`,
    '',
    `${rules.length} rules in ${families.length} families. Run \`hound explain <RULE-ID>\` for the full remediation, or \`hound scan --list-rules\` for the list in your terminal.`,
  ];
  for (const f of families) {
    out.push('', `### ${f.name} (${f.prefix})`, '');
    if (f.intro) out.push(f.intro, '');
    out.push('| ID | Severity | Rule | OWASP |', '|----|----------|------|-------|');
    for (const r of f.rules) {
      out.push(`| ${r.id} | ${SEVERITY[r.severity] ?? r.severity} | ${cell(r.title)} | ${(r.owasp ?? []).join(', ')} |`);
    }
  }
  out.push('', END);
  return out.join('\n');
}

/** README text with the rules block and rule counts brought up to date. */
function updateReadme(readme, rules) {
  const start = readme.indexOf(START);
  const end = readme.indexOf(END);
  if (start === -1 || end === -1 || end < start) throw new Error(`README.md must contain ${START} and ${END}`);
  const families = groupRules(rules).length;
  const updated = readme.slice(0, start) + renderRules(rules) + readme.slice(end + END.length);
  return updated.replace(
    /\*\*\d+ security rules\*\* \| Across \d+ families/,
    `**${rules.length} security rules** | Across ${families} families`,
  );
}

module.exports = { FAMILIES, renderRules, updateReadme };

if (require.main === module) {
  const fs = require('fs');
  const path = require('path');
  const { allRules } = require('../dist/rules/index.js');
  const file = path.join(__dirname, '..', 'README.md');
  const before = fs.readFileSync(file, 'utf8');
  const after = updateReadme(before, allRules);
  if (after !== before) fs.writeFileSync(file, after, 'utf8');
  console.log(after === before ? 'README.md is up to date' : 'Updated README.md');
}
