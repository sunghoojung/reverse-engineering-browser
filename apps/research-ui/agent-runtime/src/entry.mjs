// Browser entry for the bundle: one global the agent dock loads on demand.
import {createAgentRuntime, trimHistory, composeUserMessage, HISTORY_BYTES} from './runtime.mjs';

globalThis.RebAgentRuntime = Object.freeze({createAgentRuntime, trimHistory, composeUserMessage, HISTORY_BYTES});
