// Owned regression: method breaks this.
function vm(code,stack){var pc=0;this.ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};const other={step(){while(pc<code.length){this.ops[code[pc++]]();}}};other.step();return stack;}
