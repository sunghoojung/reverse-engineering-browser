export var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};function vm(code,stack){var pc=0;while(pc<code.length){ops[code[pc++]]();}return stack;}
