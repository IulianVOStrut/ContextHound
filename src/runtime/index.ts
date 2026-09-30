import { runInspect, evaluateBlocked } from './inspect.js';
import { HoundBlockedError } from './types.js';
import type { RuntimeMessage, InspectResult, GuardConfig } from './types.js';
export { HoundBlockedError } from './types.js';
export { RUNTIME_DEFAULT_RULES } from './inspect.js';
export type {
  RuntimeMessage,
  ContentPart,
  RuntimeFinding,
  GuardAction,
  GuardPolicy,
  InspectResult,
  GuardConfig,
} from './types.js';

export interface HoundGuard {
  /**
   * Inspect a message array. Returns findings and score without taking any
   * action: the caller decides what to do with the result.
   */
  inspect(messages: RuntimeMessage[]): InspectResult;

  /**
   * Wrap an async LLM call. Inspects `messages` before calling `fn`.
   * Throws `HoundBlockedError` if the policy blocks the call.
   * Returns the call result unmodified on pass.
   */
  wrap<T>(messages: RuntimeMessage[], fn: () => Promise<T>): Promise<T>;
}

/**
 * Create a reusable guard instance.
 *
 * @example
 * ```ts
 * import { createGuard } from 'context-hound/runtime';
 *
 * const guard = createGuard({ policy: { critical: 'block', high: 'warn' } });
 *
 * // Standalone inspection
 * const result = guard.inspect(messages);
 *
 * // Wrapped call: throws HoundBlockedError if blocked
 * const response = await guard.wrap(messages, () =>
 *   openai.chat.completions.create({ model: 'gpt-4o', messages })
 * );
 * ```
 */
export function createGuard(config: GuardConfig = {}): HoundGuard {
  const languageHint = config.languageHint ?? 'ts';
  const { policy, onInspect, onBlock, extraRules } = config;

  function inspect(messages: RuntimeMessage[]): InspectResult {
    const start = Date.now();
    const { findings, score, scoreLabel } = runInspect(
      messages,
      policy,
      languageHint,
      extraRules,
    );
    const blocked = evaluateBlocked(findings, score, policy);
    const durationMs = Date.now() - start;

    const result: InspectResult = { findings, score, scoreLabel, blocked, durationMs };

    onInspect?.(result, messages);
    if (blocked) onBlock?.(result, messages);

    return result;
  }

  async function wrap<T>(
    messages: RuntimeMessage[],
    fn: () => Promise<T>,
  ): Promise<T> {
    const result = inspect(messages);
    if (result.blocked) {
      throw new HoundBlockedError(result, messages);
    }
    return fn();
  }

  return { inspect, wrap };
}
