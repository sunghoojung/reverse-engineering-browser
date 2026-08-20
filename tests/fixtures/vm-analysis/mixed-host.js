const bytecode = new Uint8Array([1, 2, 0]);

export function runMixed(instance) {
  const stack = [];
  let ip = 0;
  while (ip < bytecode.length) {
    const handler = instance.exports.handlers[bytecode[ip++]];
    stack.push(handler(stack.pop()));
    if (bytecode[ip] === 0) return stack.pop();
  }
  return 0;
}
