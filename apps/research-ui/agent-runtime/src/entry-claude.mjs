// Browser entry for the claude bundle. The agent dock loads it on demand.
import {createAgentRuntime, HISTORY_BYTES} from './runtime.mjs';
import {createClaudeModel} from './claude.mjs';

globalThis.RebAgentRuntimes = Object.freeze({...globalThis.RebAgentRuntimes, claude: Object.freeze({
  createAgentRuntime: options => createAgentRuntime({...options, createModel: createClaudeModel}), HISTORY_BYTES,
})});
