import {test} from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {validateDocumentExchangeCredential,fetchDocumentExchangeCredential,documentExchangePath,documentExchangeRole,documentExchangePolicy} from '../../src/m365/document-exchange-custody.mjs';
const pair=()=>generateKeyPairSync('rsa',{modulusLength:3072});const a=pair(),b=pair();
const pub=(k,kid)=>({...k.export({format:'jwk'}),kid,alg:'RS256',use:'sig'});
const trust={schemaVersion:1,clientA:pub(a.publicKey,'document-gateway-1'),clientB:pub(b.publicKey,'document-gateway-2')};
const record={schemaVersion:1,purpose:'document-exchange-clients',clientAKeyPem:a.privateKey.export({format:'pem',type:'pkcs8'}),clientBKeyPem:b.privateKey.export({format:'pem',type:'pkcs8'})};
test('dedicated document client custody validates both exact public pins and distinct private keys',()=>{
 assert.deepEqual(validateDocumentExchangeCredential(record,trust),record);
 for(const r of [{...record,clientBKeyPem:record.clientAKeyPem},{...record,purpose:'portal-gateway-executor'},{...record,unexpected:'secret'},{...record,clientAKeyPem:'private'}])assert.throws(()=>validateDocumentExchangeCredential(r,trust),/Document exchange credential unavailable/);
 for(const t of [{...trust,clientA:{...trust.clientA,d:'private'}},{...trust,clientB:trust.clientA},{...trust,clientA:{...trust.clientA,kid:'old-client'}}])assert.throws(()=>validateDocumentExchangeCredential(record,t));
});
test('runtime reads only the exact Vault record with a one-use short lease',async()=>{
 const paths=[];const call=async(path,options)=>{paths.push(path);if(path==='/auth/tool-cert/login'){assert.equal(options.body.name,documentExchangeRole);return{status:200,value:{auth:{client_token:'synthetic',policies:[documentExchangePolicy],num_uses:1,lease_duration:120}}};}assert.equal(path,documentExchangePath);assert.equal(options.token,'synthetic');return{status:200,value:{data:{metadata:{version:1},data:record}}};};
 assert.equal((await fetchDocumentExchangeCredential(call,trust)).version,1);assert.deepEqual(paths,['/auth/tool-cert/login',documentExchangePath]);
});
test('wrong lease, default policy, failed read and record version drift fail closed',async()=>{
 for(const patch of [{num_uses:2},{lease_duration:121},{lease_duration:0},{policies:[documentExchangePolicy,'default']},{client_token:'bad\nvalue'}]){let reads=0;await assert.rejects(fetchDocumentExchangeCredential(async(path)=>{if(path!== '/auth/tool-cert/login')reads++;return{status:200,value:{auth:{client_token:'synthetic',policies:[documentExchangePolicy],num_uses:1,lease_duration:120,...patch}}};},trust));assert.equal(reads,0);}
 for(const result of [{status:403},{status:200,value:{data:{metadata:{version:2},data:record}}}])await assert.rejects(fetchDocumentExchangeCredential(async path=>path==='/auth/tool-cert/login'?{status:200,value:{auth:{client_token:'synthetic',policies:[documentExchangePolicy],num_uses:1,lease_duration:120}}}:result,trust));
});
