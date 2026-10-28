function vm(code,stack){var pc=0;{const ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};while(pc<code.length){ops[code[pc++]]();}}return stack;}
