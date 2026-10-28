function run(code, stack){var pc=0; do switch(code[pc++]){case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;} while(pc<code.length);}
