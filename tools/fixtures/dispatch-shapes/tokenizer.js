// Repository-owned fixture. A tokenizer loop over a string. Structurally a
// cursor loop; the buffer is a string, and nothing more is claimed.
function tokenize(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    switch (s[i]) {
      case "(":
        out.push("open");
        break;
      case ")":
        out.push("close");
        break;
      case " ":
        break;
      default:
        out.push("atom");
    }
  }
  return out;
}
