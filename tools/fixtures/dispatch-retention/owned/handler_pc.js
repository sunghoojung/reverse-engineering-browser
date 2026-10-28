function vm(code,stack){var pc=0;var ops={1:function(){pc+=2;stack.push(1)},2:function(){pc+=1;stack.pop()},3:function(){pc=code.length}};while(pc<code.length){ops[code[pc]]();}return stack;}
