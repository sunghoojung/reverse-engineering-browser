function bfs(q,types){var head=0,t=0;while(head<q.length){var id=q[head++];switch(types[id]){case 0:t++;break;case 1:t+=2;break;case 2:t+=3}}return t}
