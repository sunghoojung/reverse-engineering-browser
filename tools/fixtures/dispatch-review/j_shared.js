function run(program, arg){
  var pc=0, stack=[], handlers=[];
  handlers[0]=function(){stack.push(1)};
  handlers[1]=function(){stack.pop()};
  handlers[2]=function(){stack.push(stack.pop()+stack.pop())};
  handlers[3]=function(){return stack};
  if (arg) { var op = program[pc]; handlers[op](); }
  while(pc<program.length){ handlers[program[pc++]](); }
  return stack;
}
