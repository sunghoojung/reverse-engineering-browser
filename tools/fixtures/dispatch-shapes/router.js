// Repository-owned fixture. A one-shot router: the first argument selects
// one function per call. The constants are routing labels, not opcodes.
function alpha(x) { return x + 3; }
function beta(x) { return x * 5; }
function gamma(x) { return x ^ 7; }
function route(k, x) {
  if (k === 0x1a2b) return alpha(x);
  if (k === 0x2c3d) return beta(x);
  if (k === 0x3e4f) return gamma(x);
  return -1;
}
