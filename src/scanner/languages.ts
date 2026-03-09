// Centralised LLM API trigger patterns per language.
// When a file matches the trigger, extractFromCode() emits the full file as a
// `code-block` extraction so all applicable rules can analyse its context.
// Keyed by lowercase file extension.

const LLM_TRIGGERS: Record<string, RegExp> = {
  '.py':   /from openai import|import openai|from anthropic import|langchain|litellm|google\.generativeai|\.chat\.completions\.create|\.messages\.create|ChatOpenAI|ChatAnthropic|import pickle|import torch\b/i,
  '.go':   /go-openai|openai\.NewClient|anthropic\.NewClient|"github\.com\/sashabaranov\/go-openai"/i,
  '.rs':   /async_openai|openai::Client|use openai|anthropic::Client/i,
  '.java': /ChatLanguageModel|OpenAiChatModel|AnthropicChatModel|langchain4j|spring\.ai/i,
  '.kt':   /ChatLanguageModel|OpenAiChatModel|AnthropicChatModel|langchain4j|spring\.ai/i,
  '.kts':  /ChatLanguageModel|OpenAiChatModel|AnthropicChatModel|langchain4j|spring\.ai/i,
  '.cs':   /OpenAIClient|AzureOpenAIClient|IChatCompletionService|SemanticKernel|ChatClient/i,
  '.php':  /OpenAI::client|->chat->completions|Anthropic::|use OpenAI/i,
  '.swift':/OpenAI\(token:|OpenAIKit|Anthropic\./i,
  '.rb':   /OpenAI::Client\.new|ruby-openai|Anthropic::Client/i,
  '.sh':   /curl.{0,60}api\.openai\.com|curl.{0,60}api\.anthropic\.com/i,
  '.bash': /curl.{0,60}api\.openai\.com|curl.{0,60}api\.anthropic\.com/i,
  '.vue':  /openai|anthropic|\.chat\.completions|\.messages\.create|ChatOpenAI|langchain/i,
  '.c':    /llama_|openai_|curl.{0,40}openai/i,
  '.cpp':  /llama_|openai_|curl.{0,40}openai/i,
  '.cc':   /llama_|openai_|curl.{0,40}openai/i,
  '.h':    /llama_|openai_|curl.{0,40}openai/i,
  '.hs':   /openai-hs|anthropic-hs/i,
};

export function getLLMTrigger(ext: string): RegExp | null {
  return LLM_TRIGGERS[ext] ?? null;
}
