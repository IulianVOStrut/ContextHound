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
    mitre: 'T1190',
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
    mitre: 'T1195',
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
    mitre: 'T1548',
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
    mitre: 'T1557',
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
    mitre: 'T1059',
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
  {
    id: 'MCP-006',
    title: 'MCP confused deputy — auth token from MCP request forwarded to downstream API without re-validation',
    severity: 'critical',
    confidence: 'medium',
    category: 'mcp',
    mitre: 'T1550',
    remediation:
      'Never forward an auth token received from an MCP client directly as the credential for a downstream API call. The MCP server is acting as a deputy: it must independently verify that the requesting client is authorised to use the downstream resource. Issue a fresh credential scoped to the specific request, or introspect the inbound token before forwarding.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Only fire in files that also make outbound HTTP calls
      if (!/\bfetch\s*\(|\baxios\b|\bgot\s*\.|\brequire\s*\(\s*['"`]node-fetch|\bhttp\.request\b/i.test(text)) return [];

      // Suppress if re-validation is present
      if (/validateToken|verifyToken|introspect|re[-_]?auth|checkPermission/i.test(text)) return [];

      // Detect: Authorization header value sourced from request/params/context/event/meta
      const pattern =
        /Authorization\s*:\s*(?:`[^`\n]*\$\{[^}]*(?:request|params?|event|context|ctx|meta)\b|(?:request|params?|event|context|ctx|meta)(?:\?\.|\.)[\w?.[\]]*)/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-007',
    title: 'Cross-MCP context poisoning — shared state written from MCP output without integrity check',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    remediation:
      'Never write raw MCP tool responses directly into shared or global context stores that are accessible to other MCP servers or agents. A compromised MCP server can poison shared state and influence the behaviour of all downstream consumers. Hash or sign values before writing, validate provenance on read, or isolate each MCP server\'s context namespace.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Suppress if integrity checks are present
      if (/hash|hmac|sign(?:ature)?|verify|checksum|provenance/i.test(text)) return [];

      // Detect: shared/global context store written with a variable (not a literal)
      // Require RHS to start with a word-start char while excluding known literals
      const pattern =
        /(?:shared(?:Context|State|Memory|Cache)|global(?:Context|State|McpState|Memory)|crossMcp|agentContext)\s*(?:\[[^\]]+\]|\.\w+)?\s*=\s*(?!null\b|undefined\b|false\b|true\b|['"`\d])[a-z_$]/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-008',
    title: 'MCP stdio transport command loaded from variable path',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    mitre: 'T1195',
    remediation:
      'The command path for StdioClientTransport or StdioServerTransport must be a static string literal or a value resolved from a trusted, allowlisted configuration source. A path sourced from user input, an environment variable without validation, or an LLM-generated value enables an attacker to redirect the transport to a malicious binary.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Detect: new Stdio*Transport({ command: <variable> }) — variable, not a string literal
      const pattern =
        /new\s+Stdio(?:Client|Server)Transport\s*\(\s*\{[^}]*\bcommand\s*:\s*(?!['"`])[a-z_$][a-z0-9_$.[\]]*/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-009',
    title: 'MCP session ID used as auth decision without expiry check',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    remediation:
      'Never rely solely on a matching sessionId or connectionId for authorisation decisions without verifying the session has not expired. Sessions without TTL or timestamp validation are vulnerable to replay attacks: an attacker who captures a valid session ID can reuse it indefinitely.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Suppress if expiry/TTL logic is present
      if (/expir|ttl|maxAge|validUntil|expiresAt|isExpired|sessionAge|renewSession/i.test(text)) return [];

      // Detect: sessionId/connectionId used in an equality comparison (auth gate)
      const pattern =
        /(?:session(?:Id|Token|Key)|connection(?:Id|Key)|clientSessionId)\s*[!=]={1,2}\s*\S/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-011',
    title: 'MCP tool description contains prompt injection instruction verbs',
    severity: 'critical',
    confidence: 'high',
    category: 'mcp',
    mitre: 'T1190',
    remediation:
      'Validate MCP tool description fields against a content allowlist before registering them. A malicious MCP server can embed prompt injection instructions inside tool descriptions that are then forwarded to an LLM. Description fields must contain only documentation text — never imperative instruction phrases.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      if (!MCP_CONTEXT_PATTERN.test(prompt.text)) return [];

      const results: RuleMatch[] = [];
      const lines = prompt.text.split('\n');

      // Detect a description: string field whose value contains injection-like phrases.
      // The regex matches the field key, then captures the string value and checks it
      // for imperative override language.
      const descFieldPattern = /\bdescription\s*:\s*['"`]/i;
      const injectionVerbPattern =
        /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|override\s+(?:your\s+)?(?:system|safety|guidelines?)|disregard\s+(?:all\s+)?(?:guidelines?|instructions?|rules?)|you\s+are\s+now\s+(?:a|an)\s+(?:different|unrestricted|uncensored)|from\s+now\s+on\s+(?:you|ignore|act))/i;

      lines.forEach((line, i) => {
        if (descFieldPattern.test(line) && injectionVerbPattern.test(line)) {
          results.push({
            evidence: line.trim(),
            lineStart: prompt.lineStart + i,
            lineEnd: prompt.lineStart + i,
          });
        }
      });

      return results;
    },
  },
  {
    id: 'MCP-012',
    title: 'MCP tool name contains prompt control keywords or suspicious characters',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    remediation:
      'MCP tool names must be simple, descriptive identifiers. Names containing prompt control keywords (system, override, inject, admin, eval) or non-alphanumeric control characters may be used to confuse the LLM\'s tool-selection logic or smuggle instructions through the tool name field.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      if (!MCP_CONTEXT_PATTERN.test(prompt.text)) return [];

      // Detect server.tool() or server.setRequestHandler() calls where the name
      // string literal contains suspicious keywords or non-alphanumeric characters.
      const pattern =
        /(?:server|McpServer)\.tool\s*\(\s*['"`][^'"`\n]*(?:system|override|inject|eval|admin|root|sudo|[<>{};|&$])[^'"`\n]*['"`]/i;
      return matchPattern(prompt, pattern);
    },
  },
  {
    id: 'MCP-010',
    title: 'MCP transport event payload injected into LLM context without sanitisation',
    severity: 'critical',
    confidence: 'medium',
    category: 'mcp',
    mitre: 'T1190',
    remediation:
      'Never pass raw MCP transport event or message payloads directly into LLM message arrays or prompt strings. A malicious MCP server can craft event payloads that contain prompt injection instructions. Validate and sanitise event data against a strict schema before including it in any LLM context.',
    check(prompt: ExtractedPrompt): RuleMatch[] {
      if (prompt.kind !== 'code-block') return [];
      const text = prompt.text;
      if (!MCP_CONTEXT_PATTERN.test(text)) return [];

      // Detect: event/message payload field used in messages.push or content: assignment
      const pattern =
        /(?:messages?\.push|content\s*:)\s*(?:\{[^}\n]*)?\b(?:event|msg|message|e|data|payload)\s*(?:\?\.|\.)?\s*(?:data|content|text|body|payload)\b/i;
      return matchPattern(prompt, pattern);
    },
  },
];
