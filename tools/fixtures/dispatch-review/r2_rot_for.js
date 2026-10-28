function r(code){var pc=0,acc=0,op;for(op=code[pc++];op;op=code[pc++]){switch(op){case 1:acc++;break;case 2:acc--;break;case 3:return acc}}return acc}
