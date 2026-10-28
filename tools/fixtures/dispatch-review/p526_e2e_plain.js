function route(k,x,stack){const handlers={1:function(){stack.push(x)},2:function(){stack.pop()},3:function(){stack.length=0}};for(const v of x){log(v);}return handlers[k](x);}
