// Owned regression: other receiver write.
function vm(code,stack){var pc=0;this.ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};const other={};other.ops={};while(pc<code.length){this.ops[code[pc++]]();}return stack;}
