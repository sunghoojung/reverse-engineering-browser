// Browser entry for the chatgpt bundle. The agent dock loads it on demand.
import {createAgentRuntime, HISTORY_BYTES} from './runtime.mjs';
import {createChatGPTModel} from './chatgpt.mjs';

globalThis.RebAgentRuntimes = Object.freeze({...globalThis.RebAgentRuntimes, chatgpt: Object.freeze({
  createAgentRuntime: options => createAgentRuntime({...options, createModel: createChatGPTModel}), HISTORY_BYTES,
})});
