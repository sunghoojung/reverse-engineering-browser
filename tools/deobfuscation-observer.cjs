'use strict';

// Trusted-fixture observer, preloaded before the source without prepending to
// or wrapping it. This preserves its directives and top-level lexical scope.
// This is not a sandbox for captured or otherwise untrusted JavaScript.
const SafeError = Error;
const SafeSet = Set;
const setHas = Function.prototype.call.bind(Set.prototype.has);
const setAdd = Function.prototype.call.bind(Set.prototype.add);
const arrayPush = Function.prototype.call.bind(Array.prototype.push);
const arrayIsArray = Array.isArray;
const arrayPrototype = Array.prototype;
const objectPrototype = Object.prototype;
const getPrototypeOf = Object.getPrototypeOf;
const getDescriptors = Object.getOwnPropertyDescriptors;
const hasOwn = Object.hasOwn;
const ownKeys = Reflect.ownKeys;
const setPrototypeOf = Object.setPrototypeOf;
const defineProperty = Object.defineProperty;
const stringify = JSON.stringify;
const isProxy = require('node:util').types.isProxy;
const writeSync = require('node:fs').writeSync;
const SafeArrayBuffer = ArrayBuffer;
const SafeDataView = DataView;
const setFloat64 = Function.prototype.call.bind(DataView.prototype.setFloat64);
const getUint8 = Function.prototype.call.bind(DataView.prototype.getUint8);
const positiveInfinity = 1 / 0;
const negativeInfinity = -1 / 0;
const hex = '0123456789abcdef';

// Every array in the observation protocol has a null prototype. Capturing
// JSON.stringify alone would still invoke a fixture's inherited toJSON hook.
function tag(...items) {
  setPrototypeOf(items, null);
  return items;
}

function observe(result, completion, effects) {
  const seen = new SafeSet();
  const bits = new SafeDataView(new SafeArrayBuffer(8));
  let nodes = 0;
  let textBudget = 1048576;
  const reserveText = length => {
    textBudget -= length;
    if (textBudget < 0) throw new SafeError('observation output budget exceeded');
  };
  const encode = (value, depth = 0) => {
    if (++nodes > 10000 || depth > 64) throw new SafeError('observation budget exceeded');
    reserveText(96);
    if (value === null) return tag('null');
    switch (typeof value) {
      case 'undefined': return tag('undefined');
      case 'boolean': return tag('boolean', value);
      case 'string':
        if (value.length > 65536) throw new SafeError('observation string budget exceeded');
        reserveText(value.length * 6);
        return tag('string', value);
      case 'number': {
        if (value !== value) return tag('number', 'NaN');
        if (value === positiveInfinity) return tag('number', '+Infinity');
        if (value === negativeInfinity) return tag('number', '-Infinity');
        setFloat64(bits, 0, value, false);
        let encoded = '';
        for (let index = 0; index < 8; index++) {
          const byte = getUint8(bits, index);
          encoded += hex[byte >> 4] + hex[byte & 15];
        }
        return tag('number', encoded);
      }
      case 'object': break;
      default: throw new SafeError('unsupported observation type');
    }
    if (isProxy(value)) throw new SafeError('proxy observation');
    if (setHas(seen, value)) throw new SafeError('cyclic or shared observation object');
    setAdd(seen, value);
    const array = arrayIsArray(value);
    const prototype = getPrototypeOf(value);
    if (prototype !== (array ? arrayPrototype : objectPrototype) && prototype !== null) {
      throw new SafeError('unsupported observation prototype');
    }
    const descriptors = getDescriptors(value);
    const keys = ownKeys(descriptors);
    if (keys.length > 10000) throw new SafeError('observation property budget exceeded');
    const entries = tag();
    // Do not use fixture-mutable Array iterators, map, push or descriptor helpers.
    for (let index = 0; index < keys.length; index++) {
      const key = keys[index];
      if (typeof key !== 'string') throw new SafeError('symbol observation key');
      const descriptor = descriptors[key];
      if (!hasOwn(descriptor, 'value')) throw new SafeError('accessor observation');
      if (array && key === 'length') continue;
      reserveText(key.length * 6 + 16);
      arrayPush(entries, tag(key, encode(descriptor.value, depth + 1)));
    }
    return array ? tag('array', descriptors.length.value, entries)
      : tag('object', prototype === null ? 'null' : 'plain', entries);
  };
  if (completion !== 'normal' && completion !== 'throw') throw new SafeError('unsupported completion kind');
  const observation = tag('observation', completion, encode(result), encode(effects));
  const text = stringify(observation);
  if (text.length > 1048576) throw new SafeError('observation output budget exceeded');
  // Bypass fixture mutations to process.stdout.write and its stream methods.
  writeSync(1, text);
}

defineProperty(globalThis, '__rebObserveFixtureV2', {
  value: observe, writable: false, configurable: false, enumerable: false,
});
