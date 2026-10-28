// Owned regression: assignment after loop.
function vm(code,stack){var pc=0;while(pc<code.length){this.ops[code[pc++]]();}this.ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};return stack;}
