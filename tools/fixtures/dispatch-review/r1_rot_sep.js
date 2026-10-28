function r(code){var pc=0,acc=0;var op=code[pc];pc++;while(op){switch(op){case 1:acc++;break;case 2:acc--;break;case 3:return acc}op=code[pc];pc+=1}return acc}
