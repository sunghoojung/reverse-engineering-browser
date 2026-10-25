function (kind, exportName, offset, length) {
  // This is an explicitly requested target-side operation, not a read-only
  // sandbox. Built-ins may have been replaced by the target.
  let memory = this;
  if (kind === 'instance') {
    const getExports = Object.getOwnPropertyDescriptor(WebAssembly.Instance.prototype, 'exports').get;
    const exports = Reflect.apply(getExports, this, []);
    const descriptor = Object.getOwnPropertyDescriptor(exports, exportName);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      throw new Error('Selected export is missing or is not a data property');
    }
    memory = descriptor.value;
  }
  const getBuffer = Object.getOwnPropertyDescriptor(WebAssembly.Memory.prototype, 'buffer').get;
  const buffer = Reflect.apply(getBuffer, memory, []);
  const byteLength = buffer.byteLength;
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || length < 1 || length > 4096 || offset < 0 || offset > byteLength || length > byteLength - offset) {
    throw new Error('Memory slice is outside the current buffer or exceeds 4096 bytes');
  }
  const source = new Uint8Array(buffer, offset, length);
  const bytes = [];
  for (let i = 0; i < length; i++) bytes[i] = source[i];
  return {byte_length: byteLength, offset, length, bytes, shared: typeof SharedArrayBuffer === 'function' && buffer instanceof SharedArrayBuffer};
}
