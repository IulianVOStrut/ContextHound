import type { Rule } from './types.js';
import { injectionRules } from './injection.js';
import { exfiltrationRules } from './exfiltration.js';
import { jailbreakRules } from './jailbreak.js';
import { unsafeToolsRules } from './unsafeTools.js';
import { commandInjectionRules } from './commandInjection.js';
import { ragRules } from './rag.js';
import { encodingRules } from './encoding.js';
import { outputHandlingRules } from './outputHandling.js';
import { multimodalRules } from './multimodal.js';
import { skillsRules } from './skills.js';
import { agenticRules } from './agentic.js';
import { mcpRules } from './mcp.js';

export const allRules: Rule[] = [
  ...injectionRules,
  ...exfiltrationRules,
  ...jailbreakRules,
  ...unsafeToolsRules,
  ...commandInjectionRules,
  ...ragRules,
  ...encodingRules,
  ...outputHandlingRules,
  ...multimodalRules,
  ...skillsRules,
  ...agenticRules,
  ...mcpRules,
];

export { injectionRules, exfiltrationRules, jailbreakRules, unsafeToolsRules, commandInjectionRules, ragRules, encodingRules, outputHandlingRules, multimodalRules, skillsRules, agenticRules, mcpRules };
export type { Rule, RuleMatch } from './types.js';
export { calcRiskPoints, ruleToFinding } from './types.js';
export { scoreMitigations } from './mitigation.js';
