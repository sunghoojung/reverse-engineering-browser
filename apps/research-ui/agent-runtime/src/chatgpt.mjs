// ChatGPT through the official LangChain chat model and OpenAI SDK, on the
// Responses API. zdrEnabled keeps nothing at OpenAI: `store: false`, with
// encrypted reasoning replayed from local history.
import {ChatOpenAI} from '@langchain/openai';
import {PLACEHOLDER_KEY, MAX_OUTPUT_TOKEN_LIMIT} from './runtime.mjs';

export function createChatGPTModel({model, fetch}) {
  return new ChatOpenAI({
    model, apiKey: PLACEHOLDER_KEY, streaming: true, useResponsesApi: true, zdrEnabled: true,
    maxTokens: MAX_OUTPUT_TOKEN_LIMIT, configuration: {fetch, dangerouslyAllowBrowser: true},
  });
}
