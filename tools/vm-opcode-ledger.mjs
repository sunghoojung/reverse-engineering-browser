// Preserve the synchronous CLI API while sharing all validation with the UI.
import {createHash} from 'node:crypto';
import ledger from '../apps/research-ui/vm_opcode_ledger.js';
export const ledgerLimits = ledger.ledgerLimits;
export const inspectLedger = (input, definitionText) => ledger.inspectWithHash(input, definitionText, value => createHash('sha256').update(value).digest('hex'));
