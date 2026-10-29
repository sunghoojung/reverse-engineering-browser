// Repository-owned fixture. Minified interpreter forms: comma declarations,
// a for loop without an update clause, and a statement-form do-while.
function a(c){for(var p=0,s=0;p<c.length;){var o=c[p++],v=c[p];switch(o){case 1:s+=v;p++;break;case 2:s-=1;break;case 3:return s}}return s}
function b(c,t){var p=0;do switch(c[p++]){case 1:t.push(c[p++]);break;case 2:t.pop();break;case 3:return t}while(p<c.length);return t}
