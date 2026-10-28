function vm(code,stack){var pc=0;var ops={1:()=>{stack.push(code[pc++])},2:()=>{stack.pop()},3:()=>{pc=code.length}};while(pc<code.length){ops[code[pc++]]();}return stack;}
