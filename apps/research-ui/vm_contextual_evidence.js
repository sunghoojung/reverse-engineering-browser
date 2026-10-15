/* Offline linkage of supplied observations; never captures or executes guest code. */
const vmContextualEvidence = (() => {
  const node = typeof module === 'object' && module?.exports && typeof require === 'function';
  const model = node ? require('./vm_contextual.js') : vmContextual;
  const json = node ? require('./captured_client.js').capturedClientJSON : (...args) => capturedClientJSON(...args);
  const fail = message => { throw new TypeError(message); };
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
  const integer = (value, min, max) => Number.isSafeInteger(value) && !Object.is(value,-0) && value >= min && value <= max;
  const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(value);
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(value);
  const state = value => value === null || identifier(value);
  const limits = Object.freeze({input_bytes:1048576,events:4096,gaps:256});
  function document(input) {
    if (typeof input === 'string') {
      if (input.length > limits.input_bytes || new TextEncoder().encode(input).length > limits.input_bytes) fail('Contextual VM JSON exceeds 1 MiB.');
      const numbers = new Map(), value = json(input,numbers);
      for (const token of numbers.values()) if (!/^(0|-?[1-9][0-9]*)$/.test(token) || !Number.isSafeInteger(Number(token))) fail('Contextual VM numbers require canonical safe integer tokens.');
      return document(value);
    }
    let nodes = 0, remainingBytes = limits.input_bytes;
    const charge = bytes => {
      remainingBytes -= bytes;
      if (remainingBytes < 0) fail('Contextual VM JSON exceeds 1 MiB.');
    };
    // Count JSON's exact UTF-8 representation without materializing an escaped
    // string or the document. Repeated references consume the budget each time.
    function chargeString(value) {
      charge(2); // quotes
      for (let index = 0; index < value.length; index++) {
        const code = value.charCodeAt(index);
        if (code === 34 || code === 92) charge(2);
        else if (code < 32) charge([8,9,10,12,13].includes(code) ? 2 : 6);
        else if (code < 128) charge(1);
        else if (code < 2048) charge(2);
        else if (code >= 0xd800 && code <= 0xdbff) {
          const next = value.charCodeAt(index+1);
          if (next >= 0xdc00 && next <= 0xdfff) { charge(4); index++; }
          else charge(6); // JSON.stringify escapes unpaired surrogates.
        } else charge(code >= 0xdc00 && code <= 0xdfff ? 6 : 3);
      }
    }
    const active = new Set();
    function copy(value, depth) {
      if (++nodes > 50000 || depth > 16) fail('Contextual VM JSON structure exceeds bounds.');
      if (value === null || typeof value === 'boolean') { charge(value === false ? 5 : 4); return value; }
      if (typeof value === 'number') { if (!Number.isSafeInteger(value) || Object.is(value,-0)) fail('Contextual VM numbers require exact safe integers.'); charge(String(value).length); return value; }
      if (typeof value === 'string') { chargeString(value); return value; }
      if (typeof value !== 'object' || active.has(value)) fail('Contextual VM input must contain JSON data only.');
      const prototype = Object.getPrototypeOf(value), array = Array.isArray(value);
      if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) fail('Contextual VM input must contain plain JSON data.');
      const keys = Reflect.ownKeys(value);
      if (keys.length > 50001) fail('Contextual VM JSON structure exceeds bounds.');
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (keys.some(key => typeof key !== 'string' || key !== 'length' && (!descriptors[key].enumerable || !Object.hasOwn(descriptors[key],'value')))) fail('Contextual VM input cannot contain accessors or hidden properties.');
      active.add(value);
      let result;
      if (array) {
        if (value.length > 50000 || keys.length !== value.length + 1 || !keys.every(key => key === 'length' || /^(0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length)) fail('Contextual VM arrays must be dense JSON arrays.');
        charge(2+Math.max(0,value.length-1));
        result = Array.from({length:value.length},(_,i) => copy(descriptors[String(i)].value,depth+1));
      } else {
        charge(2+Math.max(0,keys.length-1));
        result = Object.fromEntries(keys.map(key => {
          chargeString(key); charge(1); // property colon
          return [key,copy(descriptors[key].value,depth+1)];
        }));
      }
      active.delete(value);
      return result;
    }
    return copy(input,0);
  }
  const identityKeys = ['build_id','definition_id','image_id','image_bytes_sha256','definition_canonical_sha256'];
  const contextId = (pc,decoderState) => 'context:'+pc+':'+(decoderState === null ? '?' : decoderState);
  function parseEvidence(input) {
    const value = document(input);
    if (!exact(value,['format','identity','capture_id','run_id','context_id','mapping_provenance','events','gaps']) ||
        value.format !== 'reb-vm-contextual-evidence-v1' || !exact(value.identity,identityKeys) ||
        !identityKeys.every(key => key.endsWith('sha256') ? hash(value.identity[key]) : identifier(value.identity[key])) ||
        !['capture_id','run_id','context_id'].every(key => identifier(value[key])) ||
        !exact(value.mapping_provenance,['kind','reference']) || value.mapping_provenance.kind !== 'supplied' || !identifier(value.mapping_provenance.reference) ||
        !Array.isArray(value.events) || value.events.length > limits.events || !Array.isArray(value.gaps) || value.gaps.length > limits.gaps) fail('Invalid contextual runtime evidence.');
    let previous = -1;
    const ids = new Set();
    for (const event of value.events) {
      if (!exact(event,['event_id','sequence','kind','pc','decoder_state','raw_opcode','to']) || !identifier(event.event_id) || ids.has(event.event_id) ||
          !integer(event.sequence,0,Number.MAX_SAFE_INTEGER) || event.sequence <= previous || !['step','jump'].includes(event.kind) ||
          !integer(event.pc,0,65535) || !state(event.decoder_state) || typeof event.raw_opcode !== 'string' || !/^(?:[a-f0-9]{2}){1,2}$(?![\s\S])/.test(event.raw_opcode) ||
          (event.kind === 'step' ? event.to !== null : !exact(event.to,['pc','decoder_state']) || !integer(event.to.pc,0,65535) || !state(event.to.decoder_state))) fail('Invalid runtime event or event ordering.');
      ids.add(event.event_id); previous = event.sequence;
    }
    previous = -1;
    for (const gap of value.gaps) {
      if (!exact(gap,['after_sequence','missing_count']) || !integer(gap.after_sequence,0,Number.MAX_SAFE_INTEGER) || gap.after_sequence < previous ||
          !integer(gap.missing_count,1,Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(gap.after_sequence+gap.missing_count)) fail('Invalid runtime gap.');
      if (value.events.some(event => event.sequence > gap.after_sequence && event.sequence <= gap.after_sequence+gap.missing_count)) fail('Runtime gap overlaps a retained event.');
      previous = gap.after_sequence+gap.missing_count;
    }
    return value;
  }

  async function link(definition,image,evidenceInput,options = {}) {
    // Never accept an imported analysis report as trusted decoding or identity.
    const evidence = parseEvidence(evidenceInput), analysis = await model.analyze(definition,image,options);
    if (!identityKeys.every(key => evidence.identity[key] === analysis.identity[key])) fail('Runtime evidence identity does not match reanalyzed definition and image.');
    const byId = new Map(analysis.instructions.map(item => [item.id,item]));
    const stops = new Map(analysis.diagnostics.map(item => [contextId(item.offset,item.decoder_state),item.code]));
    const declaredById = new Map();
    for (const edge of analysis.cfg.edges) {
      if (!declaredById.has(edge.from_instruction_id)) declaredById.set(edge.from_instruction_id,[]);
      declaredById.get(edge.from_instruction_id).push(edge);
    }
    const links = [], observed_edges = [], diagnostics = [];
    const endpoint = (pc,decoder_state) => {
      const id = contextId(pc,decoder_state);
      if (pc >= analysis.coverage.total_bytes) return {instruction_id:null,status:'out_of_range'};
      if (decoder_state === null) return {instruction_id:null,status:'unknown_state'};
      if (byId.has(id)) return {instruction_id:id,status:'linked'};
      return {instruction_id:null,status:stops.get(id) ?? 'not_decoded'};
    };
    for (let index=0;index<evidence.events.length;index++) {
      const event = evidence.events[index], previous = evidence.events[index-1];
      if (previous && event.sequence-previous.sequence > 1) diagnostics.push({code:'sequence_gap',after_sequence:previous.sequence,missing_count:event.sequence-previous.sequence-1});
      let source = endpoint(event.pc,event.decoder_state);
      // Compare bytes even for unknown-state/unreachable contexts. An observation
      // with mismatched bytes cannot attach an observed edge to this image.
      const raw = analysis.image.bytes_hex.slice(event.pc*2,(event.pc+analysis.definition.opcode_bytes)*2);
      if (source.status !== 'out_of_range' && (event.raw_opcode !== raw || event.raw_opcode.length !== analysis.definition.opcode_bytes*2)) source = {instruction_id:null,status:'opcode_mismatch'};
      links.push({event_id:event.event_id,sequence:event.sequence,...source});
      if (source.status !== 'linked') diagnostics.push({code:source.status,event_id:event.event_id,sequence:event.sequence});
      if (event.kind !== 'jump') continue;
      const destination = endpoint(event.to.pc,event.to.decoder_state);
      const declared = declaredById.get(source.instruction_id) ?? [];
      const agrees = event.to.decoder_state !== null && declared.some(edge => edge.to_offset === event.to.pc && edge.to_decoder_state === event.to.decoder_state);
      observed_edges.push({event_id:event.event_id,sequence:event.sequence,
        from_instruction_id:source.instruction_id,from_offset:event.pc,from_decoder_state:event.decoder_state,from_status:source.status,
        to_instruction_id:destination.instruction_id,to_offset:event.to.pc,to_decoder_state:event.to.decoder_state,to_status:destination.status,
        kind:'observed_jump',evidence:'supplied_runtime',status:source.status === 'linked' ? 'observed' : 'unlinked',
        declared_relation:source.status !== 'linked' || event.to.decoder_state === null ? 'unknown' : agrees ? 'matches_declared' : declared.some(edge => edge.to_offset === null || edge.to_decoder_state === null) ? 'unresolved_declared' : 'differs_from_declared',
        capture_id:evidence.capture_id,run_id:evidence.run_id,context_id:evidence.context_id,mapping_provenance:{...evidence.mapping_provenance}});
    }
    for (const gap of evidence.gaps) diagnostics.push({code:'reported_gap',...gap});
    return {format:'reb-vm-contextual-evidence-analysis-v1',analysis,evidence,links,observed_edges,diagnostics,complete:false,
      warnings:['Runtime observations and mapping provenance are supplied claims, not authenticated capture or proof of semantics.',
        'Declared CFG and observed jumps remain separate. Unobserved paths are unknown; no decoy or reachability conclusion follows.',
        'Events never seed decoding, infer missing state, bridge gaps, or execute code. Not-decoded destinations remain unlinked.',
        'All provenance identifiers and diagnostic values must be rendered as inert text. No raw captures are uploaded or persisted.']};
  }
  return {parseEvidence,link,limits};
})();
if (typeof module === 'object' && module?.exports) module.exports = vmContextualEvidence;
