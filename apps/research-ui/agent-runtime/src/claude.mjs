// Claude through the official LangChain chat model and Anthropic SDK.
import {ChatAnthropic} from '@langchain/anthropic';
import {PLACEHOLDER_KEY, MAX_OUTPUT_TOKEN_LIMIT} from './runtime.mjs';

const DEFAULT_FALLBACK_MODELS = new Set(['claude-fable-5-1', 'claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5']);

export function createClaudeModel({model, fetch}) {
  const fallback = DEFAULT_FALLBACK_MODELS.has(model);
  return new ChatAnthropic({
    model, apiKey: PLACEHOLDER_KEY, maxTokens: MAX_OUTPUT_TOKEN_LIMIT, streaming: true,
    clientOptions: {fetch, dangerouslyAllowBrowser: true},
    // Re-run a declined request on Anthropic's recommended model, routed by
    // refusal category, instead of ending the turn.
    ...(fallback ? {betas: ['server-side-fallback-2026-07-01'], invocationKwargs: {fallbacks: 'default'}} : {}),
  });
}
