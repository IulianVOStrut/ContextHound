// Output escaping for report formatters.
//
// Evidence, file paths and suppression reasons come straight from the files
// being scanned, which may be attacker-controlled (a malicious pull request is
// the obvious case). Every formatter that writes those values into a format
// with its own control syntax must escape them for that format.

// C0 controls except TAB, DEL, C1 controls, zero-width characters, bidi
// embeddings/overrides/isolates and the BOM. These can rewrite a terminal
// (ANSI/OSC sequences) or visually reorder text (Trojan Source).
const TERMINAL_UNSAFE =
  /[\u0000-\u0008\u000A-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** Render invisible and control characters as visible `<U+XXXX>` markers. */
export function toTerminalSafe(value: string): string {
  return value.replace(TERMINAL_UNSAFE, ch =>
    `<U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}>`,
  );
}

// Spreadsheet apps evaluate cells that start with these characters as
// formulas, even inside a quoted CSV field (CWE-1236).
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

/** Escape a value for a CSV cell, neutralising formula injection. */
export function escapeCsvCell(value: string | number): string {
  if (typeof value === 'number') return String(value);
  const s = FORMULA_TRIGGER.test(value) ? `'${value}` : value;
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Escape the message part of a GitHub Actions workflow command. */
export function escapeAnnotationData(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** Escape a property value (file=, title=) of a GitHub Actions workflow command. */
export function escapeAnnotationProperty(value: string): string {
  return escapeAnnotationData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/**
 * Wrap a value in a Markdown code span that it cannot close early. The fence
 * is one backtick longer than the longest backtick run in the value, so
 * neither Markdown nor inline HTML inside it is interpreted.
 */
export function markdownCode(value: string): string {
  const flat = value.replace(/[\r\n]+/g, ' ');
  const longestRun = Math.max(0, ...(flat.match(/`+/g) ?? []).map(r => r.length));
  const fence = '`'.repeat(longestRun + 1);
  const pad = flat.startsWith('`') || flat.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${flat}${pad}${fence}`;
}

/** Escape text for HTML element content or a double/single-quoted attribute. */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Escape a value for a Markdown table cell: inline HTML, pipes and line breaks. */
export function escapeMarkdownCell(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ');
}

// Characters that are not allowed anywhere in an XML 1.0 document.
const XML_INVALID = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g;

/** Escape a value for XML text or attribute content, dropping invalid characters. */
export function escapeXml(value: string | number): string {
  return String(value)
    .replace(XML_INVALID, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
