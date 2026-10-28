function route(k,xs){var t=0;for(var i=0;i<xs.length;i++){switch(k){case 1:t+=xs[i];break;case 2:t-=xs[i];break;case 3:t^=xs[i]}}return t}
