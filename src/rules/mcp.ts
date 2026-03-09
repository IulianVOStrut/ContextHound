import type { Rule, RuleMatch } from './types.js';
import type { ExtractedPrompt } from '../scanner/extractor.js';

// Shared guard: only fire these rules in files that import or use the MCP SDK.
const MCP_CONTEXT_PATTERN =
  /@modelcontextprotocol\/sdk|StdioServerTransport|StdioClientTransport|SSEClientTransport|McpServer\b|CreateMessageRequestSchema/i;

function matchPattern(prompt: ExtractedPrompt, pattern: RegExp): RuleMatch[] {
  const results: RuleMatch[] = [];
  const lines = prompt.text.split('\n');
  lines.forEach((line, i) => {
    if (pattern.test(line)) {
      results.push({
        evidence: line.trim(),
        lineStart: prompt.lineStart + i,
        lineEnd: prompt.lineStart + i,
      });
    }
  });
  return results;
}

export const mcpRules: Rule[] = [
  {
    id: 'MCP-001',
    title: 'MCP tool description injected into LLM prompt without sanitization',
    severity: 'critical',
    confidence: 'high',
    category: 'mcp',
    remediation:
      'Never pass raw MCP tool descriptions directly into LLM system prompts or user messages. A malicious MCP server can embed prompt injection instructions inside tool descriptions (CVE-2025-6514 pattern). Strip or allowlist-validate description content before including it in any LLM context.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      if (!MCP_CONTEXT_PATTERN.test(prompt.text)) return [];

      // Detect tool.description (or tools[n].description) used inside:
      // 1. A messages.push() call  e.g. messages.push({ content: tool.description })
      // 2. A content: field         e.g. content: tools[0].description
      // 3. A template interpolation e.g. `...${tool.description}...`
      const pattern =
        /(?:messages?\.push\s*\([^)]*\.description|content\s*:\s*[^\n,}]*\.description|\$\{[^}]*\.description)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-002',
    title: 'MCP tool registered with dynamic name or description',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    remediation:
      'MCP tool names and descriptions should be static string literals. Dynamic values sourced from config, environment variables, or network responses allow a compromised source to register tools under arbitrary names or inject override instructions into descriptions after initial user approval (rug pull attack).',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      if (!MCP_CONTEXT_PATTERN.test(prompt.text)) return [];

      // Detect server.tool() or McpServer.tool() where the first argument is:
      // - A template literal with interpolation: `${dynamicName}`
      // - A bare identifier (variable) rather than a string literal: toolName,
      const pattern =
        /(?:server|McpServer)\.tool\s*\(\s*(?:`[^`]*\$\{[^`]*`|[a-z_$][a-z0-9_$]*\b)\s*,/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-003',
    title: 'MCP sampling/createMessage handler without human approval guard',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    remediation:
      'MCP sampling requests allow a server to initiate LLM calls on behalf of the client (CVE-2025-59536). Always require explicit user approval before fulfilling sampling/createMessage requests. Add a human-in-the-loop check (e.g. prompt the user for confirmation, or set requireHumanApproval: true) before forwarding the request to an LLM provider.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Only fire when the file handles createMessage / sampling requests
      if (!/setRequestHandler\s*\(\s*CreateMessageRequestSchema|sampling\/createMessage|createMessage/i.test(text)) return [];

      // Suppress if a human-approval guard is present
      if (/requireHumanApproval|humanInLoop|humanTurnPolicy|confirm|approve/i.test(text)) return [];

      const lines = text.split('\n');
      const results: RuleMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (/setRequestHandler\s*\(\s*CreateMessageRequestSchema|sampling\/createMessage/i.test(lines[i])) {
          results.push({
            evidence: lines[i].trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
          break; // one finding per file is enough
        }
      }
      return results;
    },
  },
  {
    id: 'MCP-004',
    title: 'MCP transport URL constructed from variable',
    severity: 'medium',
    confidence: 'medium',
    category: 'mcp',
    remediation:
      'MCP server URLs should be static configuration values, not dynamic strings built from user input or LLM output. Validate any server URL against a strict allowlist before connecting. A URL injected by an attacker could redirect your MCP client to a malicious server that serves poisoned tool definitions.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      if (!MCP_CONTEXT_PATTERN.test(prompt.text)) return [];

      // Detect: new SSEClientTransport(new URL(variable)) or new URL(`${variable}`)
      // in a file that uses an SSE-based MCP transport
      const pattern =
        /new\s+(?:SSEClientTransport|SSEServerTransport|WebSocketClientTransport)\s*\(\s*new\s+URL\s*\(\s*(?:[a-z_$][a-z0-9_$]*|`[^`]*\$\{)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-005',
    title: 'MCP stdio transport uses shell:true',
    severity: 'high',
    confidence: 'high',
    category: 'mcp',
    remediation:
      'Never set shell: true in StdioClientTransport or StdioServerTransport options. With shell: true the command string is interpreted by the OS shell, making it vulnerable to injection if any part of the command or args is user-controlled. Remove shell: true and pass command and args as separate fields; the transport will spawn the process directly without shell interpretation.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Only fire in files that use a stdio-based MCP transport
      if (!/StdioClientTransport|StdioServerTransport/i.test(text)) return [];

      // Detect shell: true anywhere in the file
      const pattern = /shell\s*:\s*true/i;
      return matchPattern(prompt, pattern);
    },
  },
];
