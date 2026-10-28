function run(code){var pc=0,stack=[],op;
while(pc<code.length){switch(code[pc++]){case 0:stack.push(1);break;case 1:stack.pop();break;case 2:return stack;}}}
