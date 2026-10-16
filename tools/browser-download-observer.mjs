import assert from 'node:assert/strict';

// Browser.downloadProgress is the completion boundary. A final filename can be
// reserved before bytes are written, without any visible .crdownload sibling.
// One explicit download is allowed per QA run; late events can never own a retry.
export function trafficBrowserDownloadObserver({timeoutMs=5000,setTimer=setTimeout,clearTimer=clearTimeout}={}) {
  let active=null,used=false,closed=false;
  const events=[];
  const finish=(error,value)=>{
    if(!active)return;
    const owner=active;active=null;clearTimer(owner.timer);
    if(error)owner.reject(error);else owner.resolve(value);
  };
  return {
    arm(frameId,filename) {
      assert(!closed&&!used,'Browser download observer is closed or already used');
      assert(typeof frameId==='string'&&frameId.length>0&&frameId.length<=256,'A verified download frame is required');
      assert(typeof filename==='string'&&filename.length>0&&filename.length<=256,'A bounded expected download filename is required');
      used=true;
      const completion=new Promise((resolve,reject)=>{active={frameId,filename,guid:null,resolve,reject,timer:null};});
      // Events, timeout, or socket failure can precede the caller awaiting it.
      completion.catch(()=>{});
      active.timer=setTimer(()=>finish(new Error('Browser download did not complete before its deadline')),timeoutMs);
      return {completion,cancel:()=>finish(new Error('Browser download observation cancelled'))};
    },
    observe(message) {
      if(!active||!['Browser.downloadWillBegin','Browser.downloadProgress'].includes(message.method))return;
      const p=message.params??{};
      if(typeof p.guid!=='string'||!p.guid.length||p.guid.length>128){finish(new Error('Invalid browser download GUID'));return;}
      const event={method:message.method,guid:p.guid,state:typeof p.state==='string'?p.state.slice(0,32):null,
        frameId:typeof p.frameId==='string'?p.frameId.slice(0,256):null,filename:typeof p.suggestedFilename==='string'?p.suggestedFilename.slice(0,256):null,
        receivedBytes:Number.isFinite(p.receivedBytes)?p.receivedBytes:null,totalBytes:Number.isFinite(p.totalBytes)?p.totalBytes:null};
      events.push(event);if(events.length>32)events.shift();
      if(message.method==='Browser.downloadWillBegin') {
        if(p.frameId!==active.frameId||p.suggestedFilename!==active.filename){finish(new Error('Unexpected browser download frame or filename'));return;}
        if(active.guid!==null){finish(new Error('More than one browser download began'));return;}
        active.guid=p.guid;return;
      }
      // An unrelated or pre-begin progress event cannot complete this download.
      if(p.guid!==active.guid)return;
      if(p.state==='canceled'){finish(new Error('Browser download was canceled'));return;}
      if(!['inProgress','completed'].includes(p.state)){finish(new Error('Invalid browser download state'));return;}
      if(p.state==='completed')finish(null,{guid:active.guid,frameId:active.frameId,filename:active.filename,state:p.state});
    },
    close(reason='Browser QA cleanup') {closed=true;finish(new Error(reason));},
    receipts:()=>events.map(event=>({...event}))
  };
}

