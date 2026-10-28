function run(code, stack){var pc=0; while(pc<code.length){switch(code[pc++]){case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;}}}
