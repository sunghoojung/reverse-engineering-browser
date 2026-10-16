// Shared browser/CLI generator; never reads capture-dependent code or starts a process.
import formats from '../apps/research-ui/captured_export_formats.js';
export async function pythonProject(...args) { return formats.pythonProject(...args); }
