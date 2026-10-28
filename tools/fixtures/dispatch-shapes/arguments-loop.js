// Repository-owned fixture. A variadic loop over the arguments object. Its
// case values are argument values, not opcodes.
function tally() {
  for (var t = 0, i = 0; i < arguments.length; i++) {
    switch (arguments[i]) {
      case 1:
        t += 1;
        break;
      case 2:
        t += 2;
        break;
      case 3:
        t += 3;
        break;
    }
  }
  return t;
}
