/* Bounded contextual decoding under supplied declarations. No guest execution. */
const vmContextual = (() => {
  const json = typeof module === 'object' && module?.exports && typeof require === 'function'
    ? require('./captured_client.js').capturedClientJSON : (...args) => capturedClientJSON(...args);
  const fail = message => { throw new TypeError(message); };
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
  const integer = (value, min, max) => Number.isSafeInteger(value) && !Object.is(value,-0) && value >= min && value <= max;
  const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(value);
  const name = value => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,31}$(?![\s\S])/.test(value);
  const canonical = value => Array.isArray(value) ? value.map(canonical) : object(value)
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key,canonical(value[key])])) : value;
  const operationRoles = Object.freeze({
    unknown:[], nop:[], stack_const:['immediate'], stack_add:[], stack_drop:[], stack_dup:[],
    register_const:['register','immediate'], register_move:['register','register'],
    register_add:['register','register','register'], load:['register','address'], store:['address','register'],
    jump:[], branch_zero:['register'], stack_branch_zero:[], call:[], return:[], halt:[]
  });
  const operationFlows = {jump:'jump',branch_zero:'branch',stack_branch_zero:'branch',call:'call',return:'return',halt:'halt'};
  const flowKinds = ['next','jump','branch','call','return','halt','unknown'];
  const limits = Object.freeze({input_bytes:1048576,image_bytes:65536,instructions:4096,mappings:4096,states:256,operations:8,entries:64});
  // Object entry points accept data, not accessors, sparse arrays, prototypes or
  // serialization hooks. Serialized input additionally rejects duplicate keys.
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

  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(value);
  const state = value => value === null || identifier(value);
  const contextId = (offset, decoderState) => 'context:'+offset+':'+(decoderState === null ? '?' : decoderState);
  const tuple = (offset, decoderState, opcode) => JSON.stringify([offset,decoderState,opcode]);

  function parseDefinition(input) {
    const value = document(input);
    if (!exact(value,['format','build_id','definition_id','image_sha256','architecture','opcode_bytes','operand_endianness','register_count','instructions','mappings']) ||
        value.format !== 'reb-vm-contextual-definition-v1' || !identifier(value.build_id) || !identifier(value.definition_id) || !hash(value.image_sha256) ||
        !['stack','register'].includes(value.architecture) || ![1,2].includes(value.opcode_bytes) || !['little','big'].includes(value.operand_endianness) ||
        !integer(value.register_count,value.architecture === 'stack' ? 0 : 1,value.architecture === 'stack' ? 0 : 64) ||
        !Array.isArray(value.instructions) || value.instructions.length < 1 || value.instructions.length > 256 ||
        !Array.isArray(value.mappings) || value.mappings.length > limits.mappings) fail('Invalid contextual definition.');
    const ids = new Set(), states = new Set(), keys = new Set();
    for (const instruction of value.instructions) {
      if (!exact(instruction,['instruction_id','mnemonic','operands','operations','flow']) || !identifier(instruction.instruction_id) || ids.has(instruction.instruction_id) ||
          !name(instruction.mnemonic) || !Array.isArray(instruction.operands) || instruction.operands.length > 8 ||
          !Array.isArray(instruction.operations) || instruction.operations.length < 1 || instruction.operations.length > limits.operations) fail('Invalid instruction declaration.');
      ids.add(instruction.instruction_id);
      const operands = new Map();
      for (const operand of instruction.operands) {
        if (!exact(operand,['name','width','signed','kind']) || !name(operand.name) || operands.has(operand.name) || ![1,2,4].includes(operand.width) ||
            typeof operand.signed !== 'boolean' || !['immediate','register','address','offset'].includes(operand.kind) ||
            ['register','address'].includes(operand.kind) && operand.signed || operand.kind === 'offset' && !operand.signed ||
            operand.kind === 'register' && value.register_count === 0) fail('Invalid operand layout or role.');
        operands.set(operand.name,operand);
      }
      const flow = instruction.flow, targeted = ['jump','branch','call'].includes(flow?.kind);
      if (!exact(flow,targeted ? ['kind','target'] : ['kind']) || !flowKinds.includes(flow.kind)) fail('Invalid contextual flow.');
      if (targeted && flow.target !== null && (!exact(flow.target,['operand','base']) || !name(flow.target.operand) ||
          !['absolute','next'].includes(flow.target.base) || operands.get(flow.target.operand)?.kind !== (flow.target.base === 'absolute' ? 'address' : 'offset'))) fail('Invalid declared target.');
      instruction.operations.forEach((semantics,index) => {
        if (!exact(semantics,['operation','args']) || typeof semantics.operation !== 'string' || !Object.hasOwn(operationRoles,semantics.operation) || !Array.isArray(semantics.args)) fail('Invalid operation.');
        const {operation,args} = semantics, roles = operationRoles[operation];
        if (args.length !== roles.length || args.some((arg,i) => !name(arg) || operands.get(arg)?.kind !== roles[i]) ||
            operation.startsWith('stack_') && value.architecture !== 'stack' ||
            (operation.startsWith('register_') || ['load','store','branch_zero'].includes(operation)) && value.architecture !== 'register') fail('Operation roles or architecture disagree.');
        if (index < instruction.operations.length-1 && (Object.hasOwn(operationFlows,operation) || operation === 'unknown')) fail('Only the final macro operation may have control flow or unknown effects.');
        if (index === instruction.operations.length-1 && operation !== 'unknown' && flow.kind !== (operationFlows[operation] ?? 'next')) fail('Final operation and flow disagree.');
      });
    }
    for (const mapping of value.mappings) {
      if (!exact(mapping,['pc','decoder_state','raw_opcode','instruction_id','next_decoder_state']) || !integer(mapping.pc,0,65535) ||
          !identifier(mapping.decoder_state) || !state(mapping.next_decoder_state) || !ids.has(mapping.instruction_id) ||
          typeof mapping.raw_opcode !== 'string' || !new RegExp('^[a-f0-9]{'+value.opcode_bytes*2+'}$(?![\\s\\S])').test(mapping.raw_opcode)) fail('Invalid contextual mapping.');
      const key = tuple(mapping.pc,mapping.decoder_state,mapping.raw_opcode);
      if (keys.has(key)) fail('Duplicate contextual mapping.');
      keys.add(key); states.add(mapping.decoder_state);
      if (mapping.next_decoder_state !== null) states.add(mapping.next_decoder_state);
    }
    if (states.size > limits.states) fail('Decoder state budget exceeded.');
    return value;
  }

  function parseImage(input) {
    const value = document(input);
    if (!exact(value,['format','image_id','definition_id','build_id','bytes_hex','entry_contexts']) || value.format !== 'reb-vm-contextual-image-v1' ||
        !identifier(value.image_id) || !identifier(value.definition_id) || !identifier(value.build_id) || typeof value.bytes_hex !== 'string' ||
        value.bytes_hex.length > limits.image_bytes*2 || !/^(?:[a-f0-9]{2})*$(?![\s\S])/.test(value.bytes_hex) ||
        !Array.isArray(value.entry_contexts) || value.entry_contexts.length < 1 || value.entry_contexts.length > limits.entries) fail('Invalid contextual image.');
    const entries = new Set();
    for (const entry of value.entry_contexts) {
      if (!exact(entry,['offset','decoder_state']) || !integer(entry.offset,0,65535) || !state(entry.decoder_state)) fail('Invalid entry context.');
      const key = tuple(entry.offset,entry.decoder_state,'');
      if (entries.has(key)) fail('Duplicate entry context.');
      entries.add(key);
    }
    return value;
  }

  async function sha256(bytes) {
    const crypto = globalThis.crypto?.subtle ? globalThis.crypto :
      typeof module === 'object' && module?.exports && typeof require === 'function' ? require('node:crypto').webcrypto : null;
    if (!crypto?.subtle) fail('SHA-256 WebCrypto unavailable.');
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),byte => byte.toString(16).padStart(2,'0')).join('');
  }

  async function analyze(definitionInput,imageInput,options = {}) {
    const definition = parseDefinition(definitionInput), image = parseImage(imageInput), settings = document(options);
    if (!object(settings) || Object.keys(settings).some(key => key !== 'max_instructions') ||
        Object.hasOwn(settings,'max_instructions') && !integer(settings.max_instructions,1,limits.instructions)) fail('Invalid instruction budget.');
    if (definition.definition_id !== image.definition_id || definition.build_id !== image.build_id) fail('Build or definition identity mismatch.');
    const bytes = Uint8Array.from(image.bytes_hex.match(/../g) ?? [],byte => parseInt(byte,16)), encoder = new TextEncoder();
    const [image_bytes_sha256,definition_canonical_sha256,definition_source_sha256,image_source_sha256] = await Promise.all([
      sha256(bytes),sha256(encoder.encode(JSON.stringify(canonical(definition)))),
      typeof definitionInput === 'string' ? sha256(encoder.encode(definitionInput)) : null,
      typeof imageInput === 'string' ? sha256(encoder.encode(imageInput)) : null
    ]);
    if (definition.image_sha256 !== image_bytes_sha256) fail('Image hash does not match this build definition.');
    const identity = {build_id:definition.build_id,definition_id:definition.definition_id,image_id:image.image_id,image_bytes_sha256,definition_canonical_sha256};
    const declarations = new Map(definition.instructions.map(item => [item.instruction_id,item]));
    const mappings = new Map(definition.mappings.map(item => [tuple(item.pc,item.decoder_state,item.raw_opcode),item]));
    const instructions = [], diagnostics = [], edges = [], pending = [], scheduled = new Set(), outcomes = new Map(), covered = new Set();
    const budget = settings.max_instructions ?? limits.instructions;
    const enqueue = (offset,decoderState) => {
      const id = contextId(offset,decoderState);
      if (!scheduled.has(id)) { scheduled.add(id); pending.push({offset,decoder_state:decoderState}); }
    };
    for (const entry of image.entry_contexts) enqueue(entry.offset,entry.decoder_state);
    const unresolved = (context,reason) => {
      outcomes.set(contextId(context.offset,context.decoder_state),reason);
      diagnostics.push({...context,code:reason});
    };
    // Each decoded instruction adds at most two contexts. Unknowns are terminal;
    // branches retain their own state and never borrow a linear neighbor's state.
    for (let index = 0; index < pending.length; index++) {
      const context = pending[index], {offset,decoder_state} = context, id = contextId(offset,decoder_state);
      if (offset < 0 || offset >= bytes.length) { unresolved(context,'out_of_range'); continue; }
      if (decoder_state === null) { unresolved(context,'unknown_state'); continue; }
      if (instructions.length >= budget) { unresolved(context,'instruction_budget'); continue; }
      if (offset+definition.opcode_bytes > bytes.length) { unresolved(context,'truncated_instruction'); continue; }
      const raw_opcode = image.bytes_hex.slice(offset*2,(offset+definition.opcode_bytes)*2);
      const mapping = mappings.get(tuple(offset,decoder_state,raw_opcode));
      if (!mapping) { unresolved(context,'unknown_mapping'); continue; }
      const declared = declarations.get(mapping.instruction_id);
      const size = definition.opcode_bytes+declared.operands.reduce((total,operand) => total+operand.width,0);
      if (offset+size > bytes.length) { unresolved(context,'truncated_instruction'); continue; }
      let position = offset+definition.opcode_bytes, invalid = false;
      const operands = declared.operands.map(operand => {
        let value = 0;
        for (let i=0;i<operand.width;i++) value += bytes[position+i]*2**(8*(definition.operand_endianness === 'little' ? i : operand.width-i-1));
        if (operand.signed && value >= 2**(operand.width*8-1)) value -= 2**(operand.width*8);
        if (operand.kind === 'register' && value >= definition.register_count) invalid = true;
        const result = {...operand,offset:position,bytes_hex:image.bytes_hex.slice(position*2,(position+operand.width)*2),value};
        position += operand.width; return result;
      });
      if (invalid) { unresolved(context,'invalid_operand'); continue; }
      const instruction = {id,offset,decoder_state,raw_opcode,instruction_id:declared.instruction_id,next_decoder_state:mapping.next_decoder_state,
        mnemonic:declared.mnemonic,size,bytes_hex:image.bytes_hex.slice(offset*2,(offset+size)*2),operands,operations:declared.operations,flow:declared.flow,
        semantics_status:declared.operations.some(item => item.operation === 'unknown') ? 'unknown' : 'declared',pseudocode:[]};
      instructions.push(instruction); outcomes.set(id,'resolved');
      for (let byte=offset;byte<offset+size;byte++) covered.add(byte);
      const addEdge = (to_offset,kind) => {
        const to_decoder_state = mapping.next_decoder_state;
        edges.push({from_instruction_id:id,from_offset:offset,from_decoder_state:decoder_state,to_instruction_id:null,to_offset,to_decoder_state,kind,status:'unknown_target',evidence:'declared_static'});
        if (to_offset !== null) enqueue(to_offset,to_decoder_state);
      };
      const next = offset+size, flow = declared.flow;
      const target = flow.target ? operands.find(operand => operand.name === flow.target.operand).value+(flow.target.base === 'next' ? next : 0) : null;
      switch (flow.kind) {
        case 'next': addEdge(next,'fallthrough'); break;
        case 'jump': addEdge(target,'jump'); break;
        case 'branch': addEdge(target,'branch_taken'); addEdge(next,'branch_not_taken'); break;
        case 'call': addEdge(target,'call'); addEdge(next,'call_continuation'); break;
        case 'return': addEdge(null,'return'); break;
        case 'unknown': addEdge(null,'unknown'); break;
      }
    }
    for (const edge of edges) {
      if (edge.to_offset === null) continue;
      const id = contextId(edge.to_offset,edge.to_decoder_state);
      edge.status = outcomes.get(id) ?? 'unknown_state';
      if (edge.status === 'resolved') edge.to_instruction_id = id;
    }
    const byInstruction = new Map();
    for (const edge of edges) {
      if (!byInstruction.has(edge.from_instruction_id)) byInstruction.set(edge.from_instruction_id,[]);
      byInstruction.get(edge.from_instruction_id).push(edge);
    }
    for (const instruction of instructions) render(instruction,byInstruction.get(instruction.id) ?? []);
    return {format:'reb-vm-contextual-analysis-v1',identity,definition,image,
      provenance:{definition_canonical_sha256,definition_source_sha256,image_bytes_sha256,image_source_sha256},instructions,
      cfg:{nodes:instructions.map(item => ({instruction_id:item.id,offset:item.offset,decoder_state:item.decoder_state,reachable:true})),edges,
        entries:image.entry_contexts.map(entry => ({...entry,status:outcomes.get(contextId(entry.offset,entry.decoder_state))})),complete:false},
      coverage:{total_bytes:bytes.length,decoded_bytes:covered.size,undecoded_bytes:bytes.length-covered.size,instruction_count:instructions.length,
        context_count:pending.length,stopped_contexts:diagnostics.length},diagnostics,pseudocode:instructions.flatMap(item => item.pseudocode),
      warnings:['Mappings, state transitions, operations and CFG edges are supplied declarations, not recovered or observed semantics.',
        'PC units are byte offsets. Contexts are distinct by PC and decoder state; overlapping contexts do not prove a unique instruction partition.',
        'Call continuations are conservative assumptions. Missing state or mapping stops only that context; no bytes or states are guessed.',
        'Pseudocode is inert abstract rendering, not executable source or a behavioral equivalence proof.',
        'Hash binding establishes retained input identity, not source authenticity, ownership or vendor compatibility.',
        'Encrypted images, seed recovery, host capture, runtime key extraction and anti-debug bypass are not implemented.'],equivalence_proven:false};
  }

  function render(instruction,edges) {
    const address = value => value < 0 ? '-0x'+(-value).toString(16).padStart(4,'0') : '0x'+value.toString(16).padStart(4,'0');
    for (const [operation_index, semantics] of instruction.operations.entries()) {
      const operands = new Map(instruction.operands.map(operand => [operand.name,operand.value]));
      const values = semantics.args.map(arg => operands.get(arg));
      const register = index => 'r'+values[index];
      const flowTarget = kind => {
        const target = edges.find(item => item.kind === kind);
        return target?.status === 'resolved' ? address(target.to_offset)+' ['+target.to_decoder_state+']' : target?.to_offset !== null && target?.to_offset !== undefined
          ? 'unresolved('+address(target.to_offset)+', '+target.status+')' : 'unknown_target';
      };
      const emit = (text,status = semantics.operation === 'unknown' ? 'unknown' : 'declared') => instruction.pseudocode.push({instruction_id:instruction.id,offset:instruction.offset,decoder_state:instruction.decoder_state,operation_index,text,status});
      switch (semantics.operation) {
        case 'unknown': emit('unknown_semantics('+instruction.mnemonic+');'); break;
        case 'nop': emit('nop;'); break;
        case 'stack_const': emit('push('+values[0]+');'); break;
        case 'stack_add': emit('right = pop(); left = pop(); push(add(left, right));'); break;
        case 'stack_drop': emit('pop();'); break;
        case 'stack_dup': emit('push(peek());'); break;
        case 'register_const': emit(register(0)+' = '+values[1]+';'); break;
        case 'register_move': emit(register(0)+' = '+register(1)+';'); break;
        case 'register_add': emit(register(0)+' = add('+register(1)+', '+register(2)+');'); break;
        case 'load': emit(register(0)+' = memory['+address(values[1])+'];'); break;
        case 'store': emit('memory['+address(values[0])+'] = '+register(1)+';'); break;
        case 'jump': emit('goto '+flowTarget('jump')+';'); break;
        case 'branch_zero': emit('if ('+register(0)+' == 0) goto '+flowTarget('branch_taken')+'; else goto '+flowTarget('branch_not_taken')+';'); break;
        case 'stack_branch_zero': emit('if (pop() == 0) goto '+flowTarget('branch_taken')+'; else goto '+flowTarget('branch_not_taken')+';'); break;
        case 'call': emit('call '+flowTarget('call')+'; assumed continuation '+flowTarget('call_continuation')+';'); break;
        case 'return': emit('return unknown_target;'); break;
        case 'halt': emit('halt;'); break;
      }
      if (semantics.operation === 'unknown' && instruction.flow.kind !== 'unknown') emit('declared flow: '+instruction.flow.kind+';', 'declared');
    }
  }
  return {parseDefinition,parseImage,analyze,limits};
})();
if (typeof module === 'object' && module?.exports) module.exports = vmContextual;
