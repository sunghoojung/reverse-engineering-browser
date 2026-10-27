// Authored retained findings for inert VM/controller model tests. No browser driver.
export async function installVmFindingsFixture() {
 const content='// Owned VM finding source fixture\n',bytes=new TextEncoder().encode(content),digest=await crypto.subtle.digest('SHA-256',bytes);
 state.artifacts=[{protocol_version:1,artifact_id:'9876',session_id:'11',navigation_id:'13',frame_id:'17',parent_artifact_id:'0',creator_event_id:'19',execution_context_id:'23',capture_origin:'dynamic_javascript',kind:'javascript',url:'https://fixture.invalid/vm-owned.js',mime_type:'text/javascript',byte_size:bytes.length,sha256:Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join(''),sensitive:false,content}];
 const analysis={contract_version:1,document_kind:'vm-analysis',document_digest:'a'.repeat(64),profile_digest:'b'.repeat(64),profile:{profile_id:'anti-bot-vm-detection-v1'},input_coverage:{complete:false,omissions:[]},mixed_findings:[],results:[{finding_id:'000000000000000000009876',artifact_id:'9876',runtime:'javascript',tier:'candidate',vm_score:20,anti_bot_score:0,status:'partial',evidence_families:['owned fixture'],related_request_ids:[],observations:Array.from({length:40},(_,i)=>({rule_id:'owned:'+i,family:'owned fixture',detail:'Owned deterministic observation '+i,weight:1,coordinate:{byte_offset:0,byte_size:bytes.length}})),coverage:{complete:false,residual_unknowns:['Synthetic fixture only']}}]};
 if(!isVmAnalysisDocument(analysis))throw Error('Invalid owned VM analysis fixture');
 state.lastValidAnalysisFindings=vmFindingsFromAnalysis(analysis);
 state.eventVmFindings=[];
 state.vmFindings=[...state.lastValidAnalysisFindings,...state.eventVmFindings];
 state.selectedVmFindingId='analysis:000000000000000000009876:artifact:9876';
 renderVmLab();
}
