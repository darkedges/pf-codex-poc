import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,readdirSync,rmSync,mkdirSync,renameSync,rmdirSync} from 'node:fs';
import {tmpdir} from 'node:os';import {resolve,sep} from 'node:path';import {randomUUID} from 'node:crypto';
import {RestrictedToolAudit} from '../src/copilot/tool-audit.ts';
import {ToolMonitor} from '../src/copilot/tool-monitor.ts';
const identity={iss:'https://issuer.test',aud:'api://copilot-tool',sub:'PRIVATE_HUMAN',act:{iss:'https://actor.test',sub:'PRIVATE_AGENT'},org_id:'PRIVATE_ORG',delegation_id:'PRIVATE_GRANT',execution_mode:'autonomous',scope:'copilot.invoke'};
test('restricted audit projects verified references, excludes raw identity/credential fields and rotates within bounds',()=>{
 const dir=mkdtempSync(resolve(tmpdir(),'tool-audit-test-'));
 try{
  const audit=new RestrictedToolAudit({directory:dir,key:Buffer.alloc(32,7),maxBytes:1024});
  for(let i=0;i<8;i++)audit.write({requestId:randomUUID(),outcome:'success',claims:identity as any,token:'PRIVATE_TOKEN',message:'PRIVATE_TEXT'} as any);
  const names=readdirSync(dir);assert.equal(names.length,2);
  const raw=names.map(n=>readFileSync(resolve(dir,n),'utf8')).join('');assert.ok(!raw.includes('PRIVATE'));const event=JSON.parse(raw.split('\n')[0]);assert.match(event.identity.humanRef,/^[a-f0-9]{64}$/);assert.equal(event.identity.executionMode,'autonomous');
  assert.equal(audit.healthy(),true);
 }finally{assert.ok(dir.startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});}
});
test('audit path failure is detected and can recover without deleting evidence',()=>{
 const dir=mkdtempSync(resolve(tmpdir(),'tool-audit-test-'));
 try{
  const audit=new RestrictedToolAudit({directory:dir,key:Buffer.alloc(32,7)}),file=resolve(dir,'tool-access.jsonl');
  renameSync(file,resolve(dir,'held'));mkdirSync(file);assert.equal(audit.healthy(),false);assert.throws(()=>audit.write({requestId:randomUUID(),outcome:'denied',code:'invalid_token'}));
  rmdirSync(file);renameSync(resolve(dir,'held'),file);assert.equal(audit.healthy(),true);
 }finally{assert.ok(dir.startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});}
});
test('monitoring accepts only bounded labels and never infers a specific revocation from generic denial',()=>{
 const monitor=new ToolMonitor();monitor.observe({event:'tool_http',operation:'tool',status:429,token:'PRIVATE'});monitor.observe({event:'protected_tool',outcome:'failure',code:'policy_denied',message:'PRIVATE'});
 monitor.readiness(false);const snapshot=monitor.snapshot(Date.now()+3600000,true);
 assert.equal(snapshot.counters.rateLimited,1);assert.equal(snapshot.counters.policyDenied,1);assert.equal(snapshot.readiness,'not_ready');assert.equal(snapshot.certificateExpiring,true);assert.ok(!JSON.stringify(snapshot).includes('PRIVATE'));assert.ok(!('grantRevoked'in snapshot.counters));
 monitor.readiness(true);assert.equal(monitor.snapshot(Date.now()+864000000,true).readiness,'ready');
});
