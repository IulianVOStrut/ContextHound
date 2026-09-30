// OWASP mapping for every built-in rule.
//
// LLM01-LLM10: OWASP Top 10 for LLM Applications (2025).
// ASI01-ASI10: OWASP Top 10 for Agentic Applications (2026).
//
// A rule lists the categories its finding is direct evidence of, not every
// category it could loosely relate to, so filtering by an ID stays useful.

export const OWASP_CATEGORIES: Record<string, string> = {
  LLM01: 'Prompt Injection',
  LLM02: 'Sensitive Information Disclosure',
  LLM03: 'Supply Chain',
  LLM04: 'Data and Model Poisoning',
  LLM05: 'Improper Output Handling',
  LLM06: 'Excessive Agency',
  LLM07: 'System Prompt Leakage',
  LLM08: 'Vector and Embedding Weaknesses',
  LLM09: 'Misinformation',
  LLM10: 'Unbounded Consumption',
  ASI01: 'Agent Goal Hijack',
  ASI02: 'Tool Misuse and Exploitation',
  ASI03: 'Identity and Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities',
  ASI05: 'Unexpected Code Execution',
  ASI06: 'Memory and Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication',
  ASI08: 'Cascading Failures',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agents',
};

export const OWASP_BY_RULE: Record<string, string[]> = {
  // Prompt injection
  'INJ-001': ['LLM01'],
  'INJ-002': ['LLM01'],
  'INJ-003': ['LLM01'],
  'INJ-004': ['LLM01', 'ASI01'],
  'INJ-005': ['LLM01'],
  'INJ-006': ['LLM01'],
  'INJ-007': ['LLM01'],
  'INJ-008': ['LLM01'],
  'INJ-009': ['LLM01'],
  'INJ-010': ['LLM01'],
  'INJ-011': ['LLM01'],
  'INJ-012': ['LLM01', 'ASI06'],
  'INJ-013': ['LLM01', 'ASI01'],
  'INJ-014': ['LLM01', 'ASI01', 'ASI07'],
  'INJ-015': ['LLM01'],
  'INJ-016': ['LLM01', 'LLM05'],

  // Exfiltration and leakage
  'EXF-001': ['LLM02'],
  'EXF-002': ['LLM07'],
  'EXF-003': ['LLM02'],
  'EXF-004': ['LLM02'],
  'EXF-005': ['LLM02'],
  'EXF-006': ['LLM02'],
  'EXF-007': ['LLM02', 'LLM07'],
  'EXF-008': ['LLM02'],

  // Jailbreak
  'JBK-001': ['LLM01'],
  'JBK-002': ['LLM01'],
  'JBK-003': ['LLM01'],
  'JBK-004': ['LLM06', 'ASI09'],
  'JBK-005': ['LLM01', 'ASI10'],
  'JBK-006': ['LLM01'],
  'JBK-007': ['LLM01', 'ASI09'],
  'JBK-008': ['LLM01'],
  'JBK-009': ['LLM01'],
  'JBK-010': ['LLM01'],
  'JBK-011': ['LLM01'],
  'JBK-012': ['LLM01'],
  'JBK-013': ['LLM01'],

  // Unsafe tools
  'TOOL-001': ['LLM06', 'ASI02'],
  'TOOL-002': ['LLM06', 'ASI02'],
  'TOOL-003': ['LLM06', 'ASI05'],
  'TOOL-004': ['LLM01', 'ASI02'],
  'TOOL-005': ['LLM06', 'ASI02'],

  // Command injection and shells
  'CMD-001': ['LLM05', 'ASI05'],
  'CMD-002': ['LLM05', 'ASI05'],
  'CMD-003': ['LLM05', 'ASI05'],
  'CMD-004': ['LLM05', 'ASI05'],
  'CMD-005': ['LLM05', 'ASI05'],
  'CMD-006': ['LLM03', 'ASI05'],
  'CMD-007': ['LLM03', 'ASI05'],
  'CMD-008': ['LLM03', 'ASI05'],

  // Retrieval
  'RAG-001': ['LLM01'],
  'RAG-002': ['LLM01', 'LLM04'],
  'RAG-003': ['LLM04', 'ASI06'],
  'RAG-004': ['LLM01', 'ASI01'],
  'RAG-005': ['LLM08'],
  'RAG-006': ['LLM08'],
  'RAG-007': ['LLM01', 'LLM08'],

  // Encoding and hidden content
  'ENC-001': ['LLM01'],
  'ENC-002': ['LLM01'],
  'ENC-003': ['LLM01'],
  'ENC-004': ['LLM01'],
  'ENC-005': ['LLM01'],
  'ENC-006': ['LLM01'],

  // Output handling
  'OUT-001': ['LLM05'],
  'OUT-002': ['LLM05', 'LLM02'],
  'OUT-003': ['LLM05', 'ASI05'],
  'OUT-004': ['LLM05', 'ASI05'],
  'OUT-005': ['LLM05', 'ASI06'],

  // Multimodal
  'VIS-001': ['LLM01'],
  'VIS-002': ['LLM02'],
  'VIS-003': ['LLM01'],
  'VIS-004': ['LLM01'],

  // Agent skills
  'SKL-001': ['LLM06', 'ASI10'],
  'SKL-002': ['LLM03', 'ASI04'],
  'SKL-003': ['LLM01', 'ASI01'],
  'SKL-004': ['LLM06', 'ASI05'],
  'SKL-005': ['LLM02', 'LLM06'],
  'SKL-006': ['LLM06', 'ASI03'],
  'SKL-007': ['LLM02'],
  'SKL-008': ['LLM03', 'ASI04'],
  'SKL-009': ['LLM09', 'ASI09'],
  'SKL-010': ['ASI10'],
  'SKL-011': ['ASI06', 'ASI10'],
  'SKL-012': ['LLM03', 'ASI10'],
  'SKL-013': ['LLM06', 'ASI09'],

  // Agentic pipelines
  'AGT-001': ['LLM07', 'ASI02'],
  'AGT-002': ['LLM10', 'ASI08'],
  'AGT-003': ['LLM04', 'ASI06'],
  'AGT-004': ['LLM01', 'ASI01'],
  'AGT-005': ['ASI03'],
  'AGT-006': ['ASI07'],
  'AGT-007': ['LLM06', 'ASI10'],
  'AGT-008': ['LLM06', 'ASI03'],
  'AGT-009': ['LLM03', 'ASI04'],
  'AGT-010': ['ASI07'],
  'AGT-011': ['ASI08'],

  // Model Context Protocol
  'MCP-001': ['LLM01', 'ASI01'],
  'MCP-002': ['ASI02'],
  'MCP-003': ['LLM06', 'ASI09'],
  'MCP-004': ['ASI02'],
  'MCP-005': ['ASI02', 'ASI05'],
  'MCP-006': ['ASI03'],
  'MCP-007': ['LLM04', 'ASI06'],
  'MCP-008': ['LLM03', 'ASI04'],
  'MCP-009': ['ASI03'],
  'MCP-010': ['LLM01', 'ASI01'],
  'MCP-011': ['LLM01', 'ASI01'],
  'MCP-012': ['LLM01', 'ASI02'],

  // Supply chain
  'SCH-001': ['LLM03', 'ASI05'],
  'SCH-003': ['LLM03', 'ASI05'],
  'SCH-004': ['LLM03', 'LLM04'],
  'SCH-005': ['LLM03', 'LLM04'],
  'SCH-006': ['LLM03', 'LLM04'],

  // Resource consumption
  'DOS-001': ['LLM10'],

  // Persistence and concealment
  'PST-001': ['LLM06', 'ASI10'],
  'PST-002': ['LLM06', 'ASI10'],
  'PST-003': ['LLM06', 'ASI10'],
  'PST-004': ['LLM06', 'ASI10'],
  'PST-005': ['ASI10'],
  'PST-006': ['ASI10'],
  'PST-007': ['ASI10'],
  'PST-008': ['LLM06', 'ASI10'],
};

/** Human-readable label, e.g. "LLM01 Prompt Injection". */
export function owaspLabel(id: string): string {
  const name = OWASP_CATEGORIES[id];
  return name ? `${id} ${name}` : id;
}
