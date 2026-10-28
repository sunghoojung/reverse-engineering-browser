function r(code){var pc=0,acc=0,op;while((op=code[pc++])!==0){switch(op){case 1:acc++;break;case 2:acc--;break;case 3:return acc}}return acc}
