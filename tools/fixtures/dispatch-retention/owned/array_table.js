function vm(code,stack){var pc=0;var ops=[function(){stack.push(code[pc++])},function(){stack.pop()},function(){pc=code.length}];while(pc<code.length){ops[code[pc++]]();}return stack;}
