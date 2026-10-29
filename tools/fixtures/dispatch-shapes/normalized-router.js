// Repository-owned fixture. A one-shot router that coerces its argument to
// an integer before testing it. The selector is still the caller's argument.
function alpha(x) { return x + 3; }
function beta(x) { return x * 5; }
function gamma(x) { return x ^ 7; }
function route(k, x) {
  k = k | 0;
  if (k === 1) return alpha(x);
  if (k === 2) return beta(x);
  if (k === 3) return gamma(x);
  return -1;
}
