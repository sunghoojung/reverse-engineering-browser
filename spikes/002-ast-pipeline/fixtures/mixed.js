const table = ["fetch", "send", "token"];
const base = 7;
const add = (left, right) => left + right;
const dead = false;

if (dead) {
  console.log("unreachable");
} else {
  window[table[0]](add(base, 5), table[2]);
}
