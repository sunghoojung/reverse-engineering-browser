import assert from 'node:assert/strict';
import {inspect} from 'node:util';
import {mkdtemp,writeFile,readFile,rm,symlink,mkdir,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {cookieDestination,parseCookieImport,readCookieImport,CookieImportError} from './cookie-import.mjs';
import {runCookieImport} from './import-browser-cookies.mjs';

if(process.argv.length!==2)throw new Error('Only offline cookie checks are available; browser import was removed.');

const origin='https://account.example.test',now=Date.now()/1000;
const name='synthetic_name_DO_NOT_REPORT',value='synthetic_value_DO_NOT_REPORT';
const row=overrides=>({domain:'account.example.test',hostOnly:true,httpOnly:true,name,path:'/',sameSite:'strict',secure:true,session:true,storeId:'0',value,...overrides});
const bytes=rows=>Buffer.from(JSON.stringify(rows));
const plan=(rows=[row()],format='chrome')=>parseCookieImport(bytes(rows),format,origin,30,now);
function safe(error){assert(error instanceof CookieImportError);assert(!String(error).includes(name));assert(!String(error).includes(value));return true;}

assert.deepEqual(cookieDestination(origin,30),{origin,host:'account.example.test',seconds:30});
for(const bad of ['http://account.example.test','https://account.example.test/','https://account.example.test/path','https://user:pass@account.example.test',
  'https://account.example.test?x=1','https://account.example.test#x','https://ACCOUNT.example.test','https://account.example.test.','https://localhost','https://127.0.0.1'])assert.throws(()=>cookieDestination(bad,30),safe);
for(const duration of [0,29,301,Infinity,30.5,'30'])assert.throws(()=>cookieDestination(origin,duration),safe);
for(const patch of [
  {domain:'.example.test'}, {domain:'other.example.test'}, {domain:'.account.example.test'}, {domain:'account.example.test.'}, {domain:'ACCOUNT.example.test'},
  {hostOnly:'true'}, {secure:1}, {httpOnly:null}, {session:'false'}, {name:''}, {name:'bad;name'}, {name:'bad=name'}, {name:'bad name'},
  {value:'line\nvalue'},{value:'quote"'},{value:'with space'},{value:'semicolon;'},{value:'comma,'},{value:'\\'}, {value:'雪'},{value:'x'.repeat(4097)},
  {path:'relative'},{path:'/bad;path'},{path:'/bad\\path'},{path:'/newline\n'},{path:'/'+'a'.repeat(1024)},
  {sameSite:'None'},{sameSite:'invented'},{sameSite:'no_restriction',secure:false},
  {session:true,expirationDate:now+100},{session:false},{session:false,expirationDate:now-1},{session:false,expirationDate:now+3},
  {session:false,expirationDate:now+401*86400},{session:false,expirationDate:Infinity},{session:false,expirationDate:'123'},
  {partitionKey:{}},{partitionKey:{topLevelSite:origin}},{partitionKey:{topLevelSite:origin,hasCrossSiteAncestor:true}},
  {firstPartyDomain:''},{storeId:'firefox-container-1'},{storeId:'2'},{unknown:'field'},
  {name:'__Secure-test',secure:false},{name:'__Host-test',hostOnly:false},{name:'__Host-test',path:'/other'},
  {name:'__Http-test',httpOnly:false},{name:'__Host-Http-test',httpOnly:false}
])assert.throws(()=>plan([row(patch)]),safe);
for(const rows of [[],Array.from({length:65},(_,n)=>row({name:'n'+n})),[row(),row()],[row(),row({name:'different',storeId:'1'})]])assert.throws(()=>plan(rows),safe);
assert.throws(()=>parseCookieImport(Buffer.alloc(262145),'chrome',origin,30,now),safe);
for(const bad of ['[{"domain":"a","domain":"b"}]','["bad"]','{"cookies":[]}','# Netscape HTTP Cookie File','[{"name":"\\ud800"}]','\ufeff[]'])assert.throws(()=>parseCookieImport(Buffer.from(bad),'chrome',origin,30,now),safe);
assert.throws(()=>parseCookieImport(Buffer.from([0xff]),'chrome',origin,30,now),safe);
assert.throws(()=>plan([row({storeId:'firefox-default'})],'firefox'),safe);
assert.throws(()=>plan([row({storeId:'firefox-default',firstPartyDomain:'example.test'})],'firefox'),safe);
assert.throws(()=>plan([row({storeId:'firefox-container-1',firstPartyDomain:''})],'firefox'),safe);
for(const sameSite of ['strict','lax','no_restriction','unspecified']) {
  const p=plan([row({sameSite,partitionKey:null})]);
  for(const output of [JSON.stringify(p),inspect(p),JSON.stringify(p.review())]){assert(!output.includes(name));assert(!output.includes(value));}
  assert.equal(p.review().cookies[0].same_site,sameSite);
}
assert.equal(plan([row({storeId:'firefox-default',firstPartyDomain:''})],'firefox').review().source_format,'firefox');
assert.equal(plan([row({hostOnly:false,domain:'.account.example.test'})]).review().cookies[0].scope,'host and subdomains');
console.log('PASS cookie export adapters: strict Chrome/Firefox subset, semantic refusals, bounds, duplicates and name/value-free inspection');

assert.equal(typeof plan().applyAndVerify,'undefined','Offline review has no browser-application capability');
const directory=await realpath(await mkdtemp(join(tmpdir(),'reb-cookie-import-check-')));
try {
  const source=join(directory,'selected.json'),content=bytes([row()]);
  await writeFile(source,content,{mode:0o600});
  assert.equal((await readCookieImport(source,'chrome',origin,30)).review().count,1);
  assert.deepEqual(await readFile(source),content);
  const link=join(directory,'link.json');await symlink(source,link);
  await assert.rejects(readCookieImport(link,'chrome',origin,30),safe);
  const inner=join(directory,'inner');await mkdir(inner);await writeFile(join(inner,'input.json'),content);
  const alias=join(directory,'alias');await symlink(inner,alias);
  for(const bad of [join(alias,'input.json'),directory,'relative.json',join(directory,'missing.json')]) {
    await assert.rejects(readCookieImport(bad,'chrome',origin,30),safe);
  }
  for(const argv of [[],['--browser','/synthetic/browser'],['--browser',source],['--help','--browser',source],['--help']]) {
    for(const interactive of [false,true]) {
      const output=[];
      const forbidden=()=>{throw new Error('Removed CLI accessed private input or launched a browser');};
      const code=await runCookieImport({argv,interactive,output:line=>output.push(line),ask:forbidden,read:forbidden,launch:forbidden});
      assert.equal(code,argv.length===1&&argv[0]==='--help'?0:2);
      assert.equal(output.length,1);assert.match(output[0],/removed/);
      for(const privateText of [source,name,value])assert(!output[0].includes(privateText));
    }
  }
  assert.deepEqual(await readFile(source),content);
} finally {await rm(directory,{recursive:true,force:true});}
console.log('PASS offline file safety and removed CLI: explicit refusal, no input reads, prompts or browser launch');
