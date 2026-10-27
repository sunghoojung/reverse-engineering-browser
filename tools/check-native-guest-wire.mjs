// Actual native encoder and artifact-backed Rust output; not a live-browser acceptance claim.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
const root = new URL('../',import.meta.url);
const source = fs.readFileSync(new URL('apps/research-ui/evidence_models.js',root),'utf8');
const model = new Function(source+'\nreturn {isBrokerEvent,isVmOpcodeWorkspaceDocument,isVmHostLinksDocument};')();
const path = process.env.REB_NATIVE_GUEST_WORKSPACE_INPUT;
const exe = process.env.REB_NATIVE_GUEST_GOLDEN;
assert(path && exe,'native golden encoder and Rust workspace required');
const doc = JSON.parse(fs.readFileSync(path,'utf8'));
assert(model.isVmOpcodeWorkspaceDocument(doc),'shipped UI accepts actual Rust workspace');
const row = doc.workspaces[0].native_guest_samples[0];
assert.equal(row.instance_id,'18446744073709551615');
assert.equal(doc.workspaces[0].native_guest_sample_count,1);
assert.equal(doc.workspaces[0].sample_count,0,'native guest samples are not dispatch reports');
const links = JSON.parse(fs.readFileSync(path+'.host-links.json','utf8'));
if(row.interpretation === 'verified-dataflow') assert.equal(links.workspaces[0].links[0].guest_position.instruction_pointer,1);
else assert.equal(links.workspaces[0].links[0].guest_position,null,'explicit adapter does not prove guest semantics');
assert(model.isVmHostLinksDocument(links,doc),'shipped UI preserves verified versus explicit-adapter host semantics');
for (const [key,value] of Object.entries({instruction_pointer:4,instruction_pointer_units:'instruction-index',raw_pc_bits:257,instance_id:'0',sample_index:256,memory_length:65537,pc_adjustment:'9223372036854775808',module_byte_offset:7,adapter_sha256:'bad',opcode_width:3,interpretation:'unknown'})) {
 const bad=structuredClone(doc); bad.workspaces[0].native_guest_samples[0][key]=value;
 assert.equal(model.isVmOpcodeWorkspaceDocument(bad),false,key);
}
for(const mode of ['default','wide-identities','version','size','reserved','pc-range','snapshot-limit','memory-overflow','sample-limit','digest','signed-adjustment','parent','truncated','big-endian']){
 const events=execFileSync(exe,['--case',mode],{encoding:'utf8'}).trim().split('\n').map(JSON.parse);
 const expected=[mode!=='reserved',['default','wide-identities','reserved','signed-adjustment'].includes(mode)];
 events.forEach((event,index)=>assert.equal(model.isBrokerEvent(event),expected[index],mode+' '+index));
 const python="import importlib.util,json,sys\ns=importlib.util.spec_from_file_location('validator',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nfor event in json.load(sys.stdin):\n try:m.validate_event(event,1);print('true')\n except ValueError:print('false')";
 const verdict=execFileSync('python3',['-c',python,new URL('tools/validate-evidence-store.py',root).pathname],{input:JSON.stringify(events),encoding:'utf8'}).trim().split('\n').map(v=>v==='true');
 assert.deepEqual(verdict,expected,'Python '+mode);
}
console.log('PASS actual C++ encoder → Rust artifact-backed guest workspace → JS/Python (14 wire cases); no live browser claim');
