import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {inspectServiceAudit,pruneStoppedAudit} from '../scripts/vault/service-audit-retention.mjs';
test('retention deletes eligible journal files only when stopped, preserving newer files',()=>{const d=mkdtempSync(resolve(tmpdir(),'tool-retention-')),now=Date.now(),row=at=>JSON.stringify({version:1,event:'tool_access',at:new Date(at).toISOString()})+'\n';try{writeFileSync(resolve(d,'tool-access.jsonl.1'),row(now-2*86400000));writeFileSync(resolve(d,'tool-access.jsonl'),row(now));assert.equal(inspectServiceAudit(d).files,2);assert.throws(()=>pruneStoppedAudit(d,1,false,now));assert.equal(pruneStoppedAudit(d,1,true,now),1);assert.ok(existsSync(resolve(d,'tool-access.jsonl')));assert.equal(inspectServiceAudit(d).files,1);}finally{rmSync(d,{recursive:true,force:true});}});
test('retention fails closed on partial records and unexpected files',()=>{const d=mkdtempSync(resolve(tmpdir(),'tool-retention-'));try{writeFileSync(resolve(d,'tool-access.jsonl'),'partial');assert.throws(()=>pruneStoppedAudit(d,1,true));rmSync(resolve(d,'tool-access.jsonl'));writeFileSync(resolve(d,'unrelated'),'retain');assert.throws(()=>pruneStoppedAudit(d,1,true));assert.ok(existsSync(resolve(d,'unrelated')));}finally{rmSync(d,{recursive:true,force:true});}});
