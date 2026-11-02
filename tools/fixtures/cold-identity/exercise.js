// Shared by Node's isolated vm and a future pinned d8 run. This is test
// bookkeeping over real instance references, never a native transport or ID.
(() => {
  'use strict';
  const input = JSON.parse(read('tools/fixtures/cold-identity/pairs.json'));
  const cases = [];
  function check(condition, label) {
    if (!condition) throw new Error('Cold identity fixture failed: ' + label);
  }
  function bytes(name) {
    const pair = input.pairs.find(item => item.name === name);
    check(pair && /^[0-9a-f]+$/.test(pair.wasmHex) && pair.wasmHex.length % 2 === 0,
      'owned module input');
    return Uint8Array.from(pair.wasmHex.match(/../g), byte => parseInt(byte, 16));
  }

  function harness() {
    let program = null;
    let boundInstance = null;
    let closed = false;
    let mutations = 0;
    let registeredMutations = 0;
    let mutationsBeforeInstanceReturn = 0;
    let registrations = 0;
    let detachments = 0;
    return {
      create(pair = 'deferred', eager = false) {
        check(program === null, 'one bootstrap per harness');
        program = createOwnedColdIdentityProgram(bytes(pair), () => {
          ++mutations;
          if (program === null) ++mutationsBeforeInstanceReturn;
          if (!closed && program && boundInstance === program.instance) ++registeredMutations;
        }, eager);
        check(program.module instanceof WebAssembly.Module, 'genuine module object');
        check(program.instance instanceof WebAssembly.Instance, 'genuine instance object');
        return program;
      },
      register(enabled = true) {
        if (!enabled) return 'disabled';
        if (closed) return 'lifetime-ended';
        if (mutations !== 0) return 'already-initialized';
        if (program === null) return 'instance-unavailable';
        if (boundInstance !== null) return 'already-registered';
        boundInstance = program.instance;
        ++registrations;
        return 'owned-reference-registered';
      },
      matches(instance) { return !closed && boundInstance !== null && boundInstance === instance; },
      initialize() { return program.initialize(); },
      invalidate() {
        if (closed) return;
        closed = true;
        if (boundInstance !== null) ++detachments;
        boundInstance = null;
      },
      snapshot() {
        return { mutations, registeredMutations, mutationsBeforeInstanceReturn,
          registrations, detachments, referenceReleased: boundInstance === null };
      }
    };
  }

  const cold = harness();
  check(cold.register() === 'instance-unavailable', 'no reserved or guessed identity');
  const first = cold.create();
  check(cold.snapshot().mutations === 0, 'bootstrap has no fixture state mutation');
  check(cold.register() === 'owned-reference-registered', 'cold reference registration');
  check(cold.matches(first.instance), 'registration retains the actual instance');
  check(cold.register() === 'already-registered', 'no duplicate registration');
  check(cold.initialize() === undefined, 'original Wasm return preserved');
  check(cold.snapshot().mutations === 1 && cold.snapshot().registeredMutations === 1,
    'registration precedes original import mutation');
  cases.push('deferred-instance-before-initialization');

  const other = harness();
  const second = other.create();
  check(first.instance !== second.instance, 'same exact pair has distinct instances');
  check(!cold.matches(second.instance), 'same bytes never substitute an instance');
  cases.push('same-pair-distinct-instance');

  const disabled = harness();
  disabled.create();
  check(disabled.register(false) === 'disabled', 'disabled registration');
  disabled.initialize();
  check(disabled.snapshot().mutations === 1 && disabled.snapshot().registrations === 0
    && disabled.snapshot().registeredMutations === 0, 'disabled ordinary activity');
  cases.push('disabled');

  const warm = harness();
  warm.create();
  warm.initialize();
  check(warm.register() === 'already-initialized', 'warm registration refused');
  cases.push('late-registration-refused');

  const eager = harness();
  eager.create('deferred', true);
  check(eager.snapshot().mutationsBeforeInstanceReturn === 1,
    'eager glue mutates before program returns the instance');
  check(eager.register() === 'already-initialized', 'eager glue cannot attach retroactively');
  cases.push('eager-glue-before-return-refused');

  const start = harness();
  start.create('wasm-start');
  check(start.snapshot().mutationsBeforeInstanceReturn === 1,
    'Wasm start runs before Instance construction returns');
  check(start.register() === 'already-initialized', 'Wasm start cannot attach retroactively');
  cases.push('wasm-start-before-constructor-return-refused');

  // These are explicit harness-owner notifications. They are not Blink
  // navigation/context observers; real browser wiring remains a prerequisite.
  for (const reason of ['document-replacement', 'context-release', 'instance-replacement',
    'artifact-change', 'expiry', 'explicit-detach']) {
    const owner = harness();
    const original = owner.create();
    check(owner.register() === 'owned-reference-registered', reason + ' setup');
    owner.invalidate();
    owner.invalidate();
    check(!owner.matches(original.instance), reason + ' rejects old instance');
    check(owner.register() === 'lifetime-ended', reason + ' cannot rebind');
    owner.initialize();
    const state = owner.snapshot();
    check(state.referenceReleased && state.detachments === 1
      && state.registeredMutations === 0 && state.mutations === 1,
      reason + ' releases reference and stops observation');
    cases.push(reason + '-owner-invalidation');
  }

  const throwing = createOwnedColdIdentityProgram(bytes('deferred'), () => {
    throw new Error('owned-mutation-error');
  });
  let preserved = false;
  try {
    throwing.initialize();
  } catch (error) {
    preserved = error.message === 'owned-mutation-error';
  }
  check(preserved, 'original import exception preserved');
  cases.push('original-exception');

  print(JSON.stringify({
    schema: 'reb.owned-cold-identity-result.v1',
    provenance: 'owned-synthetic',
    status: 'SCAFFOLD_ONLY_NATIVE_IDENTITY_UNTESTED',
    casesPassed: cases,
    actualWasmInstanceReferences: true,
    coldReferenceRegistration: true,
    nativeInstanceIdTested: false,
    nativeOriginalSitesTested: false,
    browserLifecycleTested: false,
    pinnedEngineVerified: false,
    originalBoundaryTransportAvailable: false,
    nativeCoverage: null,
    liveJoinTested: false,
    deterministicJoins: 0,
    parity: false,
    rawRenderingParity: false,
    productionProof: false
  }));
})();
