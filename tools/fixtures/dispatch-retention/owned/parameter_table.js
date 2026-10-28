function vm(code,stack,ops){var pc=0;ops[1]=function(){stack.push(code[pc++])};ops[2]=function(){stack.pop()};ops[3]=function(){pc=code.length};while(pc<code.length){ops[code[pc++]]();}return stack;}
