// Offline HAR 1.2 projection. Never replay, normalize source evidence or invent phases.
import traffic from '../apps/research-ui/traffic_view.js';
const fail = reason => { throw new Error('HAR export unsupported: '+reason); };
const measured = item => {
  if (item?.state !== 'available' || typeof item.value !== 'number' || !Number.isFinite(item.value) || item.value < 0) fail('required source timing is unavailable.');
  return item.value;
};
function timing(record) {
  const t = record.timing_evidence;
  if (t?.format !== 'reb-network-timing-v1' || !t.response_observed || !t.completion_observed || t.duplicate_response || t.duplicate_completion || t.response_after_completion ||
      t.response_source !== 'responseReceived' || t.completion_source !== 'loadingFinished' || t.resource_timing.state !== 'available') fail('complete unambiguous source lifecycle timing is required.');
  const start = measured(t.request_monotonic_seconds), wall = measured(t.request_wall_seconds), response = measured(t.response_monotonic_seconds), finish = measured(t.completion_monotonic_seconds);
  const f = t.resource_timing.fields, base = measured(f.requestTime);
  if (record.started_monotonic_ms !== start*1000 || base < start || wall > 253402300799.999) fail('source clocks are incompatible with the retained request or ISO date range.');
  const pair = (first,last) => {
    if (f[first]?.state === 'unavailable' && f[last]?.state === 'unavailable') return null;
    const a=measured(f[first]), b=measured(f[last]);
    if (b<a) fail('source timing interval is reversed.');
    return [a,b];
  };
  const dns=pair('dnsStart','dnsEnd'), connect=pair('connectStart','connectEnd'), ssl=pair('sslStart','sslEnd');
  if (f.workerStart?.state !== 'unavailable' || f.proxyStart?.state !== 'unavailable' || f.proxyEnd?.state !== 'unavailable') fail('worker/proxy timing cannot be represented by this exporter.');
  const sendStart=measured(f.sendStart), sendEnd=measured(f.sendEnd), headerStart=measured(f.receiveHeadersStart), headerEnd=measured(f.receiveHeadersEnd);
  const finishOffset=(finish-base)*1000, responseOffset=(response-base)*1000;
  if (sendEnd<sendStart || headerStart<sendEnd || headerEnd<headerStart || responseOffset<headerEnd || finishOffset<responseOffset ||
      dns && dns[1]>sendStart || connect && connect[1]>sendStart || dns && connect && dns[1]>connect[0] ||
      ssl && (!connect || ssl[0]<connect[0] || ssl[1]>connect[1])) fail('source phase order is inconsistent.');
  const length = interval => interval ? interval[1]-interval[0] : -1;
  const blocked=(base-start)*1000+sendStart-Math.max(0,length(dns))-Math.max(0,length(connect));
  if (blocked<0) fail('source setup phases overlap.');
  const timings={blocked,dns:length(dns),connect:length(connect),send:sendEnd-sendStart,wait:headerStart-sendEnd,receive:finishOffset-headerStart,ssl:length(ssl),
    comment:'Derived from CDP monotonic clocks. Blocked is pre-send residual excluding disjoint DNS/connection intervals; TLS overlaps connect. Receive starts at the first response header byte.'};
  const time=['blocked','dns','connect','send','wait','receive'].reduce((sum,key)=>sum+Math.max(0,timings[key]),0);
  return {startedDateTime:new Date(wall*1000).toISOString(),time,timings};
}
function body(value) {
  if (value.truncated || !['available','empty'].includes(value.state) || value.text && value.base64 || value.state==='empty' && (value.text || value.base64)) fail('complete unambiguous retained bodies are required.');
  if (value.base64) {
    const bytes=Buffer.from(value.base64,'base64');
    if (bytes.toString('base64')!==value.base64) fail('response base64 is not canonical.');
    return {size:bytes.length,text:value.base64,encoding:'base64'};
  }
  return {size:Buffer.byteLength(value.text),text:value.text};
}
function query(url) {
  const start=url.indexOf('?');
  if(start<0 || start===url.length-1)return [];
  try {return url.slice(start+1).split('&').map(pair=>{
    const index=pair.indexOf('='),name=index<0?pair:pair.slice(0,index),value=index<0?'':pair.slice(index+1);
    return {name:decodeURIComponent(name.replace(/\+/g,' ')),value:decodeURIComponent(value.replace(/\+/g,' '))};
  });} catch {fail('query bytes cannot be losslessly represented as Unicode HAR parameters.');}
}
export function harProject(source,mode='raw') {
  if (!['raw','redacted_copy'].includes(mode)) fail('unknown copy policy.');
  const raw=source.evidence.record;
  if(raw.state!=='complete' || raw.from_disk_cache || raw.from_service_worker || raw.url_truncated || raw.method_truncated ||
      raw.request.headers_truncated || raw.response.headers_truncated || !Number.isInteger(raw.status) || raw.status<100 || raw.status>599) fail('incomplete, cached, failed or truncated source data.');
  if (!/^https?:\/\//i.test(raw.url) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(raw.method)) fail('unsupported HTTP request.');
  const versions={'HTTP/1.0':'HTTP/1.0','HTTP/1.1':'HTTP/1.1','h2':'HTTP/2.0','h3':'HTTP/3.0'};
  if(!versions[raw.protocol]) fail('unknown HTTP protocol.');
  const phase=timing(raw),requestBody=body(raw.request.body),responseBody=body(raw.response.body);
  if(requestBody.encoding) fail('binary request postData cannot be represented by HAR 1.2 text.');
  if(!responseBody.encoding && responseBody.size>0) {
    const contentType=raw.response.headers.filter(([name])=>name.toLowerCase()==='content-type');
    if(contentType.length!==1) fail('text response requires an unambiguous UTF-8 media type.');
    const type=contentType[0][1];
    const parameter = /\s*;\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*(?:([!#$%&'*+.^_`|~0-9A-Za-z-]+)|"((?:[^"\\]|\\.)*)")\s*(?=;|$)/y;
    let position=type.split(';',1)[0].length,charsetSeen=false;
    while(position<type.length) {
      parameter.lastIndex=position;const match=parameter.exec(type);
      if(!match) fail('malformed response Content-Type parameters.');
      position=parameter.lastIndex;const name=match[1].toLowerCase();
      if(name==='charset') {
        const charset=match[2]??match[3].replace(/\\(.)/g,'$1');
        if(charsetSeen || !/^utf-?8$/i.test(charset)) fail('original text byte size is unknown for this charset.');
        charsetSeen=true;
      } else if(name.startsWith('charset*')) fail('extended charset declarations are unsupported.');
    }
    if(!charsetSeen && !/^application\/(?:json|[a-z0-9.-]+\+json)\s*$/i.test(type.split(';',1)[0])) fail('original text byte size is unknown for this charset.');
  }
  const record=mode==='raw'?raw:traffic.trafficCaptureDocument({captureRecord:raw},mode).record;
  const url=record.url.split('#',1)[0], headers=side=>record[side].headers.map(([name,value])=>({name,value}));
  const mime=side=>mode==='redacted_copy'?'application/octet-stream':raw[side].headers.find(([name])=>name.toLowerCase()==='content-type')?.[1] || raw[side].body.mime || 'application/octet-stream';
  // CDP text has already been transcoded; its UTF-8 length is not original entity size.
  const request={method:record.method,url,httpVersion:versions[raw.protocol],cookies:[],headers:headers('request'),queryString:query(url),headersSize:-1,bodySize:raw.request.body.state==='empty'?0:-1,
    _cookiesParsed:false,_bodySizeKnown:raw.request.body.state==='empty'};
  if(raw.request.body.state!=='empty') request.postData={mimeType:mime('request'),text:mode==='raw'?requestBody.text:'',...(mode==='redacted_copy'?{_redacted:true}:{})};
  const content={size:responseBody.size,mimeType:mime('response'),...(mode==='raw'?responseBody:{_redacted:true}),_sizeBasis:responseBody.encoding?'retained-decoded-bytes':'retained-UTF-8-text'};
  const location=record.response.headers.filter(([name])=>name.toLowerCase()==='location');
  if(location.length>1) fail('ambiguous redirect header.');
  const response={status:record.status,statusText:record.status_text,httpVersion:versions[raw.protocol],cookies:[],headers:headers('response'),content,
    redirectURL:mode==='raw'?(location[0]?.[1]??''):'',headersSize:-1,bodySize:-1,_cookiesParsed:false};
  const entry={...phase,request,response,cache:{},_reb:{format:'reb-har-entry-v1',mode,source_identity:source.identity,
    coverage:source.evidence.coverage,timing_evidence:raw.timing_evidence,
    limitations:['CDP headers are normalized and may omit wire fields; cookie objects are not parsed.','Wire header/body sizes and cache details are unknown.','Text body size describes retained UTF-8, not original entity octets.','ISO timestamp has millisecond precision; source wall seconds are retained.']}};
  const document={log:{version:'1.2',creator:{name:'Reverse Engineering Browser',version:'reb-har-v1'},entries:[entry]}};
  const bytes=Buffer.from(JSON.stringify(document,null,2)+'\n');
  if(bytes.length>2097152) fail('output exceeds 2 MiB.');
  return {document,bytes};
}
