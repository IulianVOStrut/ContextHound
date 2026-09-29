import crypto from 'crypto';
import type { Finding } from '../types.js';

// A finding's identity for baselines and SARIF partialFingerprints: rule,
// report path, whitespace-normalised evidence, and which occurrence of that
// evidence it is within the file. Line numbers are deliberately excluded so
// edits elsewhere in the file do not make known findings look new.

export const FINGERPRINT_VERSION = 'contexthound/v1';

function normaliseEvidence(evidence: string): string {
  return evidence.replace(/\s+/g, ' ').trim();
}

/** Return copies of one file's findings with `fingerprint` set. Order is preserved. */
export function assignFingerprints(findings: Finding[]): Finding[] {
  const byPosition = findings
    .map((f, index) => ({ f, index }))
    .sort((a, b) => a.f.lineStart - b.f.lineStart || a.f.id.localeCompare(b.f.id) || a.index - b.index);

  const seen = new Map<string, number>();
  const fingerprints = new Array<string>(findings.length);
  for (const { f, index } of byPosition) {
    const base = `${f.id}\0${f.file}\0${normaliseEvidence(f.evidence)}`;
    const occurrence = seen.get(base) ?? 0;
    seen.set(base, occurrence + 1);
    fingerprints[index] = crypto.createHash('sha256').update(`${base}\0${occurrence}`).digest('hex').slice(0, 32);
  }
  return findings.map((f, i) => ({ ...f, fingerprint: fingerprints[i] }));
}
