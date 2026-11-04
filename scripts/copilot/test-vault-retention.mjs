import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {prepareCaptureWriter,retireCaptureWriter,readPrivateCapture} from './vault-capture-access.mjs';
import {createVaultCaptureWriter,executeRetainedPost,captureVaultPath} from './vault-capture.mjs';
import {vault,operator,privateSave} from '../vault/common.mjs';
import {rendererCertificate} from '../vault/tool-custody.mjs';
const id=randomUUID(),path=captureVaultPath(id),checks=[];let writer,denial,clean=false;
const check=(name,v)=>{assert.ok(v,name);checks.push(name);};
try{
 writer=await prepareCaptureWriter(id);const sink=createVaultCaptureWriter(id,()=>writer.token,vault),url='https://token.botframework.com/api/sas/postToken?expiry=1800000000&id=SYNTHETIC_ID&state=SYNTHETIC_STATE&hmac=SYNTHETIC_SIG',body='{"token":"SYNTHETIC_RETENTION_ONLY"}',response='HTTP/1.1 400 Bad Request\r\nset-cookie: SYNTHETIC_COOKIE\r\n\r\n"Synthetic response"';
 await executeRetainedPost(sink,url,{method:'POST',headers:{'Content-Type':'application/json'},body},()=>({parsed:{status:400},rawResponse:response}));
 const stored=await readPrivateCapture(id);check('two CAS writes retain exact original URL and token body',stored.metadata.version===2&&stored.data.request.url===url&&stored.data.request.body===body);check('raw response is retained without projection',stored.data.rawResponse===response);check('stored state records complete request and response',stored.data.state==='request-and-response-retained');
 denial=await prepareCaptureWriter(id);check('capture writer cannot read retained secret',(await vault(path,{token:denial.token})).status===403);check('capture writer cannot read runtime credentials',(await vault('/federated-copilot-tool-secrets/data/runtime',{token:denial.token})).status===403);
 const login=await vault('/auth/tool-cert/login',{method:'POST',body:{name:'tool-runtime-renderer'},...rendererCertificate()});check('tool runtime reader cannot read debug credentials',(await vault(path,{token:login.value.auth.client_token})).status===403);
}catch{process.exitCode=1;console.error('Synthetic Vault retention verification failed; raw values withheld');}
finally{
 try{
  if(denial)await retireCaptureWriter(denial);if(writer)await retireCaptureWriter(writer);
  const r=await readPrivateCapture(id);assert.equal(JSON.parse(r.data.request.body).token,'SYNTHETIC_RETENTION_ONLY');await operator(path.replace('/data/','/metadata/'),{method:'DELETE'});clean=true;
 }catch{process.exitCode=1;}
 const receipt={completedAt:new Date().toISOString(),passed:process.exitCode!==1&&clean,checks:checks.length,syntheticRecordRemoved:clean,microsoftRequests:0};privateSave('private-capture-validation.json',receipt);console.log(JSON.stringify(receipt));
}
