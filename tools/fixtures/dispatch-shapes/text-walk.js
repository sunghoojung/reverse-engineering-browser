// Repository-owned fixture. A character scan: a cursor loop over a string
// read with charCodeAt. Its case values are character codes, not opcodes.
function count(s) {
  for (var n = 0, i = 0; i < s.length; i++) {
    switch (s.charCodeAt(i)) {
      case 10:
        n++;
        break;
      case 13:
        break;
      case 32:
        break;
    }
  }
  return n;
}
