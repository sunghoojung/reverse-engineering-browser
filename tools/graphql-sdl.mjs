// Bounded structural SDL projection, never a GraphQL query executor.
const fail=()=>{throw new Error('Unsupported or incomplete GraphQL introspection. Supply a complete bounded schema with valid names, references and literal defaults.');};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const name=value=>typeof value==='string'&&value.length<=256&&/^[_A-Za-z][_0-9A-Za-z]*$/.test(value)&&!value.startsWith('__')?value:fail();
const list=(value,max=4096)=>Array.isArray(value)&&value.length<=max?value:fail();
const unique=(items,key='name')=>{const seen=new Set();for(const item of items){const n=name(item[key]);if(seen.has(n))fail();seen.add(n);}return items;};
const description=(value,indent='')=>value===null||value===undefined?'':typeof value==='string'&&Buffer.byteLength(value)<=16384?indent+JSON.stringify(value)+'\n':fail();
const kinds=new Set(['SCALAR','OBJECT','INTERFACE','UNION','ENUM','INPUT_OBJECT']);
const builtinScalars=new Set(['Int','Float','String','Boolean','ID']);
const builtinDirectives=new Set(['skip','include','deprecated','specifiedBy','oneOf']);
const locations=new Set(['QUERY','MUTATION','SUBSCRIPTION','FIELD','FRAGMENT_DEFINITION','FRAGMENT_SPREAD','INLINE_FRAGMENT','VARIABLE_DEFINITION','SCHEMA','SCALAR','OBJECT','FIELD_DEFINITION','ARGUMENT_DEFINITION','INTERFACE','UNION','ENUM','ENUM_VALUE','INPUT_OBJECT','INPUT_FIELD_DEFINITION']);

// Validate one GraphQL constant literal before emitting it; arbitrary SDL is refused.
export function constantLiteral(source) {
  if(typeof source!=='string'||Buffer.byteLength(source)>16384)fail();
  let position=0,nodes=0;
  const space=()=>{while(position<source.length&&/[\t\n\r ,\uFEFF]/u.test(source[position]))position++;};
  function value(depth=0) {
    if(depth>32||++nodes>4096)fail();space();const start=position,c=source[position];
    if(c==='['||c==='{') {
      position++;space();const end=c==='['?']':'}',seen=new Set();
      while(source[position]!==end) {
        if(position>=source.length)fail();
        if(c==='{') {const match=/^[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(position));if(!match||seen.has(match[0]))fail();seen.add(match[0]);position+=match[0].length;space();if(source[position++]!==':')fail();}
        value(depth+1);space();
      }
      position++;return;
    }
    if(c==='"') {
      if(source.startsWith('"""',position)) {
        position+=3;
        while(position<source.length) {
          if(source.startsWith('\\"""',position)){position+=4;continue;}
          if(source.startsWith('"""',position)){position+=3;return;}
          if(source.charCodeAt(position)<32&&!['\t','\n','\r'].includes(source[position]))fail();position++;
        }
        fail();
      }
      position++;let escaped=false;
      while(position<source.length) {const ch=source[position++];if(!escaped&&ch==='"'){try{if(!JSON.parse(source.slice(start,position)).isWellFormed())fail();}catch{fail();}return;}if(!escaped&&ch==='\\')escaped=true;else escaped=false;}
      fail();
    }
    const token=/^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[_A-Za-z][_0-9A-Za-z]*)/.exec(source.slice(position));
    if(!token)fail();position+=token[0].length;
    if(position<source.length&&!/[\t\n\r ,\]}\uFEFF]/u.test(source[position]))fail();
  }
  value();space();if(position!==source.length)fail();return source.trim();
}

export function introspectionSDL(document) {
  if(!object(document)||document.errors!==undefined&&(!Array.isArray(document.errors)||document.errors.length))fail();
  const schema=document.data?.__schema??document.__schema;
  if(!object(schema))fail();
  const all=list(schema.types),types=new Map(),warnings=new Set();
  for(const type of all) {
    if(!object(type)||typeof type.name!=='string'||!kinds.has(type.kind))fail();
    if(type.name.startsWith('__'))continue;
    name(type.name);if(types.has(type.name)||builtinScalars.has(type.name)&&type.kind!=='SCALAR')fail();types.set(type.name,type);
  }
  let fieldsSeen=0;
  const members=(items)=>{const values=unique(list(items));fieldsSeen+=values.length;if(fieldsSeen>20000)fail();return values;};
  function reference(ref,input=false,depth=0) {
    if(!object(ref)||depth>32)fail();
    if(ref.kind==='NON_NULL'||ref.kind==='LIST') {
      if(ref.name!=null||!object(ref.ofType)||ref.kind==='NON_NULL'&&ref.ofType.kind==='NON_NULL')fail();
      const child=reference(ref.ofType,input,depth+1);return ref.kind==='LIST'?'['+child+']':child+'!';
    }
    const n=name(ref.name),type=types.get(n);
    if(!type||ref.kind!==type.kind||ref.ofType!=null||input&&!['SCALAR','ENUM','INPUT_OBJECT'].includes(type.kind)||!input&&type.kind==='INPUT_OBJECT')fail();
    return n;
  }
  function deprecated(item) {
    if(item.isDeprecated===undefined)return '';
    if(typeof item.isDeprecated!=='boolean')fail();
    if(!item.isDeprecated)return '';
    if(typeof item.deprecationReason!=='string')fail();
    return ' @deprecated(reason: '+JSON.stringify(item.deprecationReason)+')';
  }
  function inputValue(item,indent='') {
    const type=reference(item.type,true),defaultValue=item.defaultValue;
    // A missing property means the introspection query omitted default-value evidence.
    if(defaultValue===undefined)fail();
    const literal=defaultValue===null?'':' = '+constantLiteral(defaultValue);
    if(item.isDeprecated&&item.type.kind==='NON_NULL'&&defaultValue===null)fail();
    return description(item.description,indent)+indent+name(item.name)+': '+type+literal+deprecated(item);
  }
  function args(items) {
    const values=members(items);return values.length?'(\n'+values.map(item=>inputValue(item,'    ')).join('\n')+'\n  )':'';
  }
  function interfaces(type) {
    const items=unique(list(type.interfaces));
    for(const ref of items)if(ref.kind!=='INTERFACE'||types.get(ref.name)?.kind!=='INTERFACE')fail();
    return items.length?' implements '+items.map(ref=>name(ref.name)).join(' & '):'';
  }
  const roots=[],rootNames=new Set();
  for(const [operation,key] of [['query','queryType'],['mutation','mutationType'],['subscription','subscriptionType']]) {
    const root=schema[key];if(root==null){if(operation==='query')fail();continue;}
    const n=name(root.name);if(types.get(n)?.kind!=='OBJECT'||rootNames.has(n))fail();rootNames.add(n);roots.push('  '+operation+': '+n);
  }
  const out=[description(schema.description)+'schema {\n'+roots.join('\n')+'\n}'];
  for(const type of types.values()) {
    const n=name(type.name),desc=description(type.description);
    switch(type.kind) {
      case 'SCALAR': {
        if(builtinScalars.has(n))break;
        if(type.specifiedByURL===undefined)warnings.add('Scalar specifiedByURL was not provided; omitted annotations may be unknown.');
        if(type.specifiedByURL!=null&&typeof type.specifiedByURL!=='string')fail();
        out.push(desc+'scalar '+n+(type.specifiedByURL?' @specifiedBy(url: '+JSON.stringify(type.specifiedByURL)+')':''));break;
      }
      case 'OBJECT':case 'INTERFACE': {
        const fields=members(type.fields);if(!fields.length)fail();
        out.push(desc+(type.kind==='OBJECT'?'type ':'interface ')+n+interfaces(type)+' {\n'+fields.map(field=>
          description(field.description,'  ')+'  '+name(field.name)+args(field.args)+': '+reference(field.type)+deprecated(field)).join('\n')+'\n}');break;
      }
      case 'INPUT_OBJECT': {
        if(type.isOneOf===undefined)warnings.add('Input isOneOf was not provided; omitted OneOf constraints may be unknown.');
        const fields=members(type.inputFields);if(!fields.length||type.isOneOf!==undefined&&type.isOneOf!==null&&typeof type.isOneOf!=='boolean')fail();
        if(type.isOneOf&&fields.some(field=>field.type.kind==='NON_NULL'||field.defaultValue!==null))fail();
        out.push(desc+'input '+n+(type.isOneOf?' @oneOf':'')+' {\n'+fields.map(field=>inputValue(field,'  ')).join('\n')+'\n}');break;
      }
      case 'ENUM': {
        const values=members(type.enumValues);if(!values.length)fail();
        out.push(desc+'enum '+n+' {\n'+values.map(value=>{if(['true','false','null'].includes(value.name))fail();return description(value.description,'  ')+'  '+name(value.name)+deprecated(value);}).join('\n')+'\n}');break;
      }
      case 'UNION': {
        const possible=unique(list(type.possibleTypes));if(!possible.length)fail();
        for(const item of possible)if(item.kind!=='OBJECT'||types.get(item.name)?.kind!=='OBJECT')fail();
        out.push(desc+'union '+n+' = '+possible.map(item=>name(item.name)).join(' | '));break;
      }
      default:fail();
    }
  }
  const directives=unique(list(schema.directives,256));
  for(const directive of directives) {
    const n=name(directive.name),where=list(directive.locations,32);
    if(!where.length||new Set(where).size!==where.length||where.some(item=>!locations.has(item))||directive.isRepeatable!==undefined&&typeof directive.isRepeatable!=='boolean')fail();
    if(directive.isRepeatable===undefined&&!builtinDirectives.has(n))warnings.add('Directive isRepeatable was not provided; repeatability may be unknown.');
    const parameters=args(directive.args);
    if(!builtinDirectives.has(n))out.push(description(directive.description)+'directive @'+n+parameters+(directive.isRepeatable?' repeatable':'')+' on '+where.join(' | '));
  }
  const text='# Reconstructed from saved introspection; no query was sent.\n# Applied custom directives, resolvers and authorization are not recoverable from introspection.\n# Structural conversion does not replace full GraphQL schema validation.\n\n'+[...warnings].map(warning=>'# Limitation: '+warning+'\n').join('')+out.join('\n\n')+'\n';
  if(Buffer.byteLength(text)>1048576)fail();
  return {text,type_count:types.size,directive_count:directives.length,warnings:[...warnings]};
}
