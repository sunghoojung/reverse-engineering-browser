class VM{#ops={};run(code,stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};while(pc<code.length){this.#ops[code[pc++]]();}}}
