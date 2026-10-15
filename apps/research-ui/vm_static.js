/* Inert, bounded bytecode decoding under user-declared semantics. No VM execution. */
const vmStatic = (() => {
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
  const limits = Object.freeze({input_bytes:1048576,image_bytes:65536,opcodes:256,operands:8,entries:64,instructions:4096,edges:8192,pseudocode:8192,diagnostics:8257});

  // Object entry points accept data, not accessors, sparse arrays, prototypes or
  // serialization hooks. Serialized input additionally rejects duplicate keys.
  function document(input) {
    if (typeof input === 'string') {
      if (input.length > limits.input_bytes || new TextEncoder().encode(input).length > limits.input_bytes) fail('Static VM JSON exceeds 1 MiB.');
      const numbers = new Map(), value = json(input,numbers);
      for (const token of numbers.values()) if (!/^(0|-?[1-9][0-9]*)$/.test(token) || !Number.isSafeInteger(Number(token))) fail('Static VM numbers require canonical safe integer tokens.');
      return document(value);
    }
    let nodes = 0;
    const active = new Set();
    function copy(value, depth) {
      if (++nodes > 50000 || depth > 16) fail('Static VM JSON structure exceeds bounds.');
      if (value === null || typeof value === 'boolean') return value;
      if (typeof value === 'number') { if (!Number.isSafeInteger(value) || Object.is(value,-0)) fail('Static VM numbers require exact safe integers.'); return value; }
      if (typeof value === 'string') { if (value.length > limits.input_bytes) fail('Static VM string exceeds bounds.'); return value; }
      if (typeof value !== 'object' || active.has(value)) fail('Static VM input must contain JSON data only.');
      const prototype = Object.getPrototypeOf(value), array = Array.isArray(value);
      if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) fail('Static VM input must contain plain JSON data.');
      const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors);
      if (keys.some(key => typeof key !== 'string' || key !== 'length' && (!descriptors[key].enumerable || !Object.hasOwn(descriptors[key],'value')))) fail('Static VM input cannot contain accessors or hidden properties.');
      active.add(value);
      let result;
      if (array) {
        if (value.length > 50000 || keys.length !== value.length + 1 || !keys.every(key => key === 'length' || /^(0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length)) fail('Static VM arrays must be dense JSON arrays.');
        result = Array.from({length:value.length},(_,i) => copy(descriptors[String(i)].value,depth+1));
      } else result = Object.fromEntries(keys.map(key => [key,copy(descriptors[key].value,depth+1)]));
      active.delete(value);
      return result;
    }
    const result = copy(input,0);
    if (new TextEncoder().encode(JSON.stringify(result)).length > limits.input_bytes) fail('Static VM JSON exceeds 1 MiB.');
    return result;
  }

  function parseDefinition(input) {
    const value = document(input);
    if (!exact(value,['format','definition_id','architecture','opcode_bytes','operand_endianness','register_count','opcodes']) || value.format !== 'reb-vm-definition-v1' ||
        !identifier(value.definition_id) || !['stack','register'].includes(value.architecture) || ![1,2].includes(value.opcode_bytes) ||
        !['little','big'].includes(value.operand_endianness) || !integer(value.register_count,value.architecture === 'stack' ? 0 : 1,value.architecture === 'stack' ? 0 : 64) ||
        !Array.isArray(value.opcodes) || value.opcodes.length < 1 || value.opcodes.length > limits.opcodes) fail('Invalid bounded reb-vm-definition-v1.');
    const codes = new Set();
    for (const opcode of value.opcodes) {
      if (!exact(opcode,['code','mnemonic','operands','semantics','flow']) || typeof opcode.code !== 'string' ||
          !new RegExp('^[a-f0-9]{'+value.opcode_bytes*2+'}$(?![\\s\\S])').test(opcode.code) || codes.has(opcode.code) || !name(opcode.mnemonic) ||
          !Array.isArray(opcode.operands) || opcode.operands.length > limits.operands || !exact(opcode.semantics,['operation','args']) ||
          typeof opcode.semantics.operation !== 'string' || !Object.hasOwn(operationRoles,opcode.semantics.operation) || !Array.isArray(opcode.semantics.args)) fail('Invalid or duplicate opcode definition.');
      codes.add(opcode.code);
      const operands = new Map();
      for (const operand of opcode.operands) {
        if (!exact(operand,['name','width','signed','kind']) || !name(operand.name) || operands.has(operand.name) || ![1,2,4].includes(operand.width) ||
            typeof operand.signed !== 'boolean' || !['immediate','register','address','offset'].includes(operand.kind) ||
            ['register','address'].includes(operand.kind) && operand.signed || operand.kind === 'offset' && !operand.signed ||
            operand.kind === 'register' && value.register_count === 0) fail('Invalid operand layout or role.');
        operands.set(operand.name,operand);
      }
      const {operation,args} = opcode.semantics, roles = operationRoles[operation];
      if (args.length !== roles.length || args.some((arg,index) => !name(arg) || operands.get(arg)?.kind !== roles[index]) ||
          operation.startsWith('stack_') && value.architecture !== 'stack' ||
          (operation.startsWith('register_') || ['load','store','branch_zero'].includes(operation)) && value.architecture !== 'register') fail('Semantic operation arguments or architecture disagree.');
      const flow = opcode.flow, hasTarget = ['jump','branch','call'].includes(flow?.kind);
      if (!exact(flow,hasTarget ? ['kind','target'] : ['kind']) || !flowKinds.includes(flow.kind) ||
          operation !== 'unknown' && flow.kind !== (operationFlows[operation] ?? 'next')) fail('Semantic operation and declared flow disagree.');
      if (hasTarget && (!exact(flow.target,['operand','base']) || !name(flow.target.operand) || !['absolute','next'].includes(flow.target.base) ||
          operands.get(flow.target.operand)?.kind !== (flow.target.base === 'absolute' ? 'address' : 'offset'))) fail('Flow target requires an explicit address or signed next-relative offset operand.');
    }
    return value;
  }

  function parseImage(input) {
    const value = document(input);
    if (!exact(value,['format','image_id','definition_id','entry_offsets','bytes_hex']) || value.format !== 'reb-vm-bytecode-v1' ||
        !identifier(value.image_id) || !identifier(value.definition_id) || typeof value.bytes_hex !== 'string' ||
        value.bytes_hex.length > limits.image_bytes*2 || !/^(?:[a-f0-9]{2})*$(?![\s\S])/.test(value.bytes_hex) ||
        !Array.isArray(value.entry_offsets) || value.entry_offsets.length < 1 || value.entry_offsets.length > limits.entries ||
        !value.entry_offsets.every(offset => integer(offset,0,65535)) || new Set(value.entry_offsets).size !== value.entry_offsets.length) fail('Invalid bounded reb-vm-bytecode-v1.');
    return value;
  }

  async function sha256(bytes) {
    const crypto = globalThis.crypto?.subtle ? globalThis.crypto :
      typeof module === 'object' && module?.exports && typeof require === 'function' ? require('node:crypto').webcrypto : null;
    if (!crypto?.subtle) fail('SHA-256 WebCrypto is unavailable; analysis cannot produce verified input hashes.');
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),byte => byte.toString(16).padStart(2,'0')).join('');
  }

  async function analyze(definitionInput, imageInput, options = {}) {
    const definition = parseDefinition(definitionInput), image = parseImage(imageInput), settings = document(options);
    if (!object(settings) || Object.keys(settings).some(key => key !== 'max_instructions') ||
        Object.hasOwn(settings,'max_instructions') && !integer(settings.max_instructions,1,limits.instructions)) fail('max_instructions must be an exact integer from 1 to 4096.');
    if (image.definition_id !== definition.definition_id) fail('Bytecode image and definition IDs disagree.');
    const budget = settings.max_instructions ?? limits.instructions, bytes = Uint8Array.from(image.bytes_hex.match(/../g) ?? [],byte => parseInt(byte,16));
    const encoder = new TextEncoder();
    const [definition_canonical_sha256,definition_source_sha256,image_bytes_sha256,image_source_sha256] = await Promise.all([
      sha256(encoder.encode(JSON.stringify(canonical(definition)))),
      typeof definitionInput === 'string' ? sha256(encoder.encode(definitionInput)) : null,
      sha256(bytes), typeof imageInput === 'string' ? sha256(encoder.encode(imageInput)) : null
    ]);
    const opcodes = new Map(definition.opcodes.map(opcode => [opcode.code,opcode])), instructions = [], diagnostics = [];
    let cursor = 0, stopReason = 'end';
    const diagnostic = (offset,code,message) => diagnostics.push({offset,code,message});
    while (cursor < bytes.length) {
      if (instructions.length === budget) { stopReason = 'instruction_budget'; diagnostic(cursor,stopReason,'Instruction budget reached; remaining bytes were not decoded.'); break; }
      if (cursor + definition.opcode_bytes > bytes.length) { stopReason = 'truncated_instruction'; diagnostic(cursor,stopReason,'Incomplete literal opcode bytes; decoding stopped.'); break; }
      const opcode = image.bytes_hex.slice(cursor*2,(cursor+definition.opcode_bytes)*2), declared = opcodes.get(opcode);
      if (!declared) { stopReason = 'unknown_opcode'; diagnostic(cursor,stopReason,'Opcode '+opcode+' has no declaration; no later bytes were guessed.'); break; }
      const size = definition.opcode_bytes + declared.operands.reduce((total,operand) => total+operand.width,0);
      if (cursor + size > bytes.length) { stopReason = 'truncated_instruction'; diagnostic(cursor,stopReason,'Declared operand bytes extend beyond the retained image.'); break; }
      const operands = [];
      let position = cursor + definition.opcode_bytes, invalid = false;
      for (const operand of declared.operands) {
        let value = 0;
        for (let i = 0; i < operand.width; i++) value += bytes[position+i] * 2 ** (8*(definition.operand_endianness === 'little' ? i : operand.width-i-1));
        if (operand.signed && value >= 2 ** (operand.width*8-1)) value -= 2 ** (operand.width*8);
        if (operand.kind === 'register' && value >= definition.register_count) invalid = true;
        operands.push({...operand,offset:position,bytes_hex:image.bytes_hex.slice(position*2,(position+operand.width)*2),value});
        position += operand.width;
      }
      if (invalid) { stopReason = 'invalid_operand'; diagnostic(cursor,stopReason,'A declared register operand exceeds register_count; decoding stopped before this instruction.'); break; }
      instructions.push({id:'insn:'+cursor,offset:cursor,size,bytes_hex:image.bytes_hex.slice(cursor*2,(cursor+size)*2),opcode,mnemonic:declared.mnemonic,
        operands,operation:declared.semantics.operation,args:[...declared.semantics.args],semantics_status:declared.semantics.operation === 'unknown' ? 'unknown' : 'declared',flow:declared.flow,pseudocode:[]});
      cursor += size;
    }
    const starts = new Map(instructions.map(instruction => [instruction.offset,instruction]));
    // Linear-prefix decoding makes every decoded non-start byte an interior
    // byte. Never recursively reinterpret an operand as a branch destination.
    const targetStatus = offset => offset === null ? 'unknown' : offset < 0 || offset >= bytes.length ? 'out_of_range' :
      starts.has(offset) ? 'resolved' : offset < cursor ? 'mid_instruction' : 'undecoded';
    const edges = [], edgesByOffset = new Map();
    function edge(instruction,to_offset,kind) {
      const status = targetStatus(to_offset);
      const item = {from_offset:instruction.offset,to_offset,kind,status,evidence:'declared_static'};
      edges.push(item);
      if (!edgesByOffset.has(instruction.offset)) edgesByOffset.set(instruction.offset,[]);
      edgesByOffset.get(instruction.offset).push(item);
      if (status !== 'resolved' && status !== 'unknown') diagnostic(instruction.offset,'target_'+status,kind+' target '+to_offset+' is '+status+'.');
    }
    for (const instruction of instructions) {
      const next = instruction.offset+instruction.size, flow = instruction.flow;
      const target = flow.target ? instruction.operands.find(operand => operand.name === flow.target.operand).value + (flow.target.base === 'next' ? next : 0) : null;
      switch (flow.kind) {
        case 'next': edge(instruction,next,'fallthrough'); break;
        case 'jump': edge(instruction,target,'jump'); break;
        case 'branch': edge(instruction,target,'branch_taken'); edge(instruction,next,'branch_not_taken'); break;
        case 'call': edge(instruction,target,'call'); edge(instruction,next,'call_continuation'); break;
        case 'return': edge(instruction,null,'return'); break;
        case 'unknown': edge(instruction,null,'unknown'); break;
        case 'halt': break;
      }
    }
    const entries = image.entry_offsets.map(offset => ({offset,status:targetStatus(offset)}));
    for (const entry of entries) if (entry.status !== 'resolved') diagnostic(entry.offset,'entry_'+entry.status,'Declared entry '+entry.offset+' is '+entry.status+'.');
    const successors = new Map();
    for (const item of edges) if (item.status === 'resolved') {
      if (!successors.has(item.from_offset)) successors.set(item.from_offset,[]);
      successors.get(item.from_offset).push(item.to_offset);
    }
    const reachable = new Set(), pending = entries.filter(entry => entry.status === 'resolved').map(entry => entry.offset);
    for (let index = 0; index < pending.length; index++) {
      const offset = pending[index]; if (reachable.has(offset)) continue;
      reachable.add(offset);
      for (const next of successors.get(offset) ?? []) if (!reachable.has(next)) pending.push(next);
    }
    const address = value => value < 0 ? '-0x'+(-value).toString(16).padStart(4,'0') : '0x'+value.toString(16).padStart(4,'0');
    for (const instruction of instructions) {
      const operands = new Map(instruction.operands.map(operand => [operand.name,operand.value]));
      const values = instruction.args.map(arg => operands.get(arg));
      const register = index => 'r'+values[index];
      const flowTarget = kind => {
        const target = edgesByOffset.get(instruction.offset)?.find(item => item.kind === kind);
        return target?.status === 'resolved' ? address(target.to_offset) : target?.to_offset !== null && target?.to_offset !== undefined
          ? 'unresolved('+address(target.to_offset)+', '+target.status+')' : 'unknown_target';
      };
      const emit = (text,status = instruction.semantics_status) => instruction.pseudocode.push({instruction_id:instruction.id,offset:instruction.offset,text,status});
      switch (instruction.operation) {
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
      if (instruction.operation === 'unknown' && instruction.flow.kind !== 'unknown') emit('declared flow: '+instruction.flow.kind+';', 'declared');
    }
    return {format:'reb-vm-static-analysis-v1',definition,image,
      provenance:{definition_canonical_sha256,definition_source_sha256,image_bytes_sha256,image_source_sha256},instructions,
      cfg:{nodes:instructions.map(instruction => ({instruction_id:instruction.id,offset:instruction.offset,reachable:reachable.has(instruction.offset)})),edges,entries,complete:false},
      coverage:{decoded_bytes:cursor,total_bytes:bytes.length,instruction_count:instructions.length,stop_reason:stopReason,undecoded_bytes:bytes.length-cursor},
      pseudocode:instructions.flatMap(instruction => instruction.pseudocode),diagnostics,
      warnings:[
        'Opcode layouts, semantics, entry points and control flow are user-declared, not recovered or proven.',
        'Static CFG edges are declared possibilities, not observed execution; complete=false does not describe byte-decoding coverage.',
        'Reachable means reachable under declared static edges, including conservative assumed call continuations; it does not establish actual execution.',
        'A call_continuation is an assumed continuation only, never proof that a call returns. Calling conventions and return destinations remain unknown.',
        'The image is decoded linearly from byte zero. Embedded data, bitfield/variable opcodes, encrypted bytecode and arbitrary VM formats are unsupported.',
        'Operand widths describe byte encoding only; runtime arithmetic width, overflow, flags and memory behavior are unspecified.',
        'Pseudocode is an instruction-linked rendering of declarations, not execution, validation, stack-safety analysis, source recovery or semantic equivalence.',
        'Input identities are supplied and unauthenticated. Hashes bind these local inputs only, not a captured artifact or authorized target.',
        'Original bytecode and definitions may contain private data. No input is executed, fetched, uploaded or persisted by this model.'
      ],equivalence_proven:false};
  }
  return {parseDefinition,parseImage,analyze,limits};
})();
if (typeof module === 'object' && module?.exports) module.exports = vmStatic;
