// Preserve the CLI Buffer return contract around the shared browser generator.
import formats from '../apps/research-ui/captured_export_formats.js';
export function harProject(...args) {
  const result = formats.harProject(...args);
  return {...result,bytes:Buffer.from(result.bytes)};
}
