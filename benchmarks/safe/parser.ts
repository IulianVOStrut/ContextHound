// Small tokenizer used by the docs site; unrelated to any model call.
const WORD = /[A-Za-z]+/g;

export function words(text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = WORD.exec(text)) !== null) out.push(m[0]);
  return out;
}

export function logRequest(message: string): void {
  console.log(`received message: ${message}`);
}
