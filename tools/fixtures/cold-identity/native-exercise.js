// Test-host contract only. No native implementation, ID allocator or transport
// lives here. A future pinned cctest must install the native host before
// compiling the exact owned program; ordinary Node/d8 must exit unavailable.
(() => {
  'use strict';
  const input = JSON.parse(read('tools/fixtures/cold-identity/pairs.json'));
  const completed = [];
  let mutations = 0;
  let firstExpected = null;
  let api = null;
  function check(condition, label) {
    if (!condition) throw new Error('Native cold identity test failed: ' + label);
  }
  function bytes(name) {
    const pair = input.pairs.find(item => item.name === name);
    check(pair && /^(?:[0-9a-f]{2})+$/.test(pair.wasmHex), 'owned module bytes');
    return Uint8Array.from(pair.wasmHex.match(/../g), byte => parseInt(byte, 16));
  }
  function report(status, code) {
    print(JSON.stringify({
      schema: 'reb.owned-native-cold-identity-test.v1',
      provenance: 'owned-synthetic',
      status,
      nativeTestHostAssertionsCompleted: completed,
      coldInstanceConstructed: true,
      fixtureMutations: mutations,
      nativeInstanceIdTested: false,
      pinnedEngineVerified: false,
      nativeOriginalSitesTested: false,
      browserLifecycleTested: false,
      originalBoundaryTransportAvailable: false,
      nativeCoverage: null,
      liveJoinTested: false,
      deterministicJoins: 0,
      parity: false,
      rawRenderingParity: false,
      productionProof: false
    }));
    quit(code);
  }

  // Construct and retain an actual cold object, without warming it to discover
  // an ID. This reference is never returned or labeled as native identity.
  const first = createOwnedColdIdentityProgram(bytes('deferred'), () => {
    if (api) {
      check(api.lookupCurrent() === firstExpected, 'first import native ID');
      check(api.lookupExisting(first.instance) === firstExpected,
        'first import agrees with the actual bound object');
    }
    ++mutations;
  });
  check(first.instance instanceof WebAssembly.Instance && mutations === 0,
    'existing cold instance before native binding');

  const host = Object.getOwnPropertyDescriptor(globalThis, '__rebColdIdentityNativeTest');
  if (!host) return report('BLOCKED_NATIVE_COLD_ID_API_UNAVAILABLE', 78);
  // Reject getters/incomplete adapters without invoking them. These shape
  // checks cannot attest that a supplied function is native; only cctest can.
  if (!Object.hasOwn(host, 'value') || host.value === null || typeof host.value !== 'object') {
    return report('BLOCKED_NATIVE_COLD_ID_TEST_HOST_UNSUPPORTED', 78);
  }
  const methods = ['bindExisting', 'lookupExisting', 'lookupCurrent', 'invalidate',
    'forceFullGc'];
  for (const name of methods) {
    const descriptor = Object.getOwnPropertyDescriptor(host.value, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
      return report('BLOCKED_NATIVE_COLD_ID_TEST_HOST_UNSUPPORTED', 78);
    }
  }
  api = host.value;
  const token = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
  check(api.lookupCurrent() === null, 'no executing frame while cold');
  check(api.lookupExisting(first.instance) === null, 'no ID before bind');
  firstExpected = api.bindExisting(first.instance);
  check(token(firstExpected), 'native opaque ID required, never an object reference');
  check(mutations === 0 && api.lookupExisting(first.instance) === firstExpected,
    'native lookup before initialize');
  check(api.bindExisting(first.instance) === null, 'duplicate bind refused');
  check(api.lookupExisting(first.instance) === firstExpected, 'duplicate preserves existing ID');
  completed.push('native-lookup-before-initialize');
  check(first.initialize() === undefined && mutations === 1, 'original first import and return');
  check(api.lookupCurrent() === null, 'returned frame cannot supply current identity');
  completed.push('first-original-import-same-native-id');

  let siblingExpected = null;
  const sibling = createOwnedColdIdentityProgram(bytes('deferred'), () => {
    check(api.lookupCurrent() === siblingExpected, 'second original glue instance import');
    check(api.lookupExisting(sibling.instance) === siblingExpected, 'second original glue object');
    ++mutations;
  });
  check(api.lookupExisting(sibling.instance) === null, 'same original pair starts unbound');
  siblingExpected = api.bindExisting(sibling.instance);
  check(token(siblingExpected) && siblingExpected !== firstExpected,
    'same original glue and Wasm bytes have distinct native instances');
  completed.push('same-original-pair-distinct-instances');

  // Additional same-module case: reuse the module actually compiled from the
  // owned bytes, rather than creating a second module with equal bytes only.
  let secondExpected = null;
  const second = new WebAssembly.Instance(first.module, { owned: { mutate() {
    check(api.lookupCurrent() === secondExpected, 'second import native ID');
    check(api.lookupExisting(second) === secondExpected, 'second actual object');
    ++mutations;
  } } });
  check(api.lookupExisting(second) === null, 'second instance starts unbound');
  secondExpected = api.bindExisting(second);
  check(token(secondExpected) && secondExpected !== firstExpected
    && secondExpected !== siblingExpected, 'distinct native instance IDs');
  check(api.forceFullGc() === undefined, 'native full GC hook');
  check(api.lookupExisting(first.instance) === firstExpected
    && api.lookupExisting(sibling.instance) === siblingExpected
    && api.lookupExisting(second) === secondExpected, 'retained objects survive moving GC');
  first.initialize();
  sibling.initialize();
  second.exports.initialize();
  first.initialize();
  second.exports.initialize();
  sibling.initialize();
  check(mutations === 7, 'interleaved original imports');
  completed.push('same-module-distinct-instances-interleaved-gc');

  const old = firstExpected;
  check(api.invalidate(first.instance) === undefined, 'native invalidation');
  check(api.invalidate(first.instance) === undefined, 'idempotent native invalidation');
  firstExpected = null;
  check(api.lookupExisting(first.instance) === null && api.bindExisting(first.instance) === null,
    'invalidated object cannot be rebound in this owner');
  first.initialize();
  check(api.lookupExisting(second) === secondExpected && secondExpected !== old
    && api.lookupExisting(sibling.instance) === siblingExpected,
    'invalidation does not substitute another instance');
  completed.push('after-invalidate-fails-closed');

  for (const value of [undefined, null, {}, first.initialize,
    new Proxy(second, { get() { throw new Error('must not inspect proxy'); } })]) {
    check(api.bindExisting(value) === null && api.lookupExisting(value) === null,
      'non-instance/native-proxy input refused');
  }
  completed.push('invalid-native-input-refused');

  // A post-return native bind must refuse these, even if an internal future
  // pre-start hook could have attached earlier. No initialized flag is reset.
  for (const [name, pair, eager] of [
    ['warm', 'deferred', false], ['eager-glue', 'deferred', true],
    ['wasm-start', 'wasm-start', false]
  ]) {
    let calls = 0;
    const program = createOwnedColdIdentityProgram(bytes(pair), () => {
      check(api.lookupCurrent() === null, 'unbound import cannot borrow an ID');
      ++calls;
      ++mutations;
    }, eager);
    if (name === 'warm') program.initialize();
    check(calls === 1 && api.bindExisting(program.instance) === null
      && api.lookupExisting(program.instance) === null, name + ' post-return bind refused');
    completed.push(name + '-post-return-refused');
  }
  check(api.invalidate(second) === undefined && api.lookupExisting(second) === null,
    'release shared-module binding');
  check(api.invalidate(sibling.instance) === undefined
    && api.lookupExisting(sibling.instance) === null, 'release original pair sibling');
  check(mutations === 11, 'all authored mutations accounted for');
  // Even completing this test-host contract cannot verify native provenance,
  // binary/source identity or browser lifetimes from JavaScript.
  report('NATIVE_TEST_HOST_ASSERTIONS_ONLY', 78);
})();
