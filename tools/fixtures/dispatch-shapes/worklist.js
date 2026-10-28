// Repository-owned fixture. A worklist drain: each id comes from pop(), and
// its type is looked up by value. The index is never advanced, so this is
// not a cursor loop.
function drain(queue, types) {
  let total = 0;
  while (queue.length) {
    const id = queue.pop();
    switch (types[id]) {
      case 0:
        total += 1;
        break;
      case 1:
        total += 2;
        break;
    }
  }
  return total;
}
