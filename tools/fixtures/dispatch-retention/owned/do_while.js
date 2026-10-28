function vm(code,stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};do{ops[code[pc++]]();}while(pc<code.length);return stack;}
