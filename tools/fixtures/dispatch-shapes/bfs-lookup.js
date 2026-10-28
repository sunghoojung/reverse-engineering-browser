// Repository-owned fixture. A breadth-first walk: each id is read at the
// queue cursor, and the switch selects on types[id], a second-level lookup
// through the cursor-loaded value rather than a fetched opcode.
function walk(q, types) {
  var head = 0, total = 0;
  while (head < q.length) {
    var id = q[head++];
    switch (types[id]) {
      case 0:
        total++;
        break;
      case 1:
        total += 2;
        break;
      case 2:
        total += 3;
        break;
    }
  }
  return total;
}
