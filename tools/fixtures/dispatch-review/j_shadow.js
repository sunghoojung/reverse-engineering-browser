function run(program){
  var pc=0, stack=[], handlers=[];
  handlers[0]=function(){stack.push(1)};
  handlers[1]=function(){stack.pop()};
  handlers[2]=function(){stack.push(stack.pop()+stack.pop())};
  var opcode=program[pc++];
  handlers[opcode]();
  function other(code){ var handlers=[]; var ip=0; while(ip<code.length){ handlers[code[ip++]](); } }
  return stack;
}
