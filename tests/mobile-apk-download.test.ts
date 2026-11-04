import test from 'node:test';import assert from 'node:assert/strict';import {apkHandler,apkPath} from '../scripts/mobile-apk-download.mjs';
test('APK endpoint serves only the pinned route and refuses other paths, queries, methods and expiry',()=>{
 const bytes=Buffer.from('synthetic APK'),run=(url,method='GET',now=0)=>{let status,body,headers;apkHandler(bytes,100,()=>now)({url,method},{writeHead:(s,h)=>{status=s;headers=h;},end:b=>body=b});return{status,body,headers};};
 assert.equal(run(apkPath).status,200);assert.deepEqual(run(apkPath).body,bytes);assert.equal(run(apkPath,'HEAD').body,undefined);
 for(const path of ['/',apkPath+'?x=1','/downloads/../secret',apkPath+'/'])assert.equal(run(path).status,404);
 assert.equal(run(apkPath,'POST').status,404);assert.equal(run(apkPath,'GET',100).status,404);
});
test('diagnostic APK routes remain fixed and cannot select other files',()=>{const bytes=Buffer.from('diagnostic fixture');for(const version of [6,7,8,9]){let status,headers,body;const path=`/downloads/federated-copilot-v${version}.apk`;apkHandler(bytes,100,()=>0,path)({url:path,method:'GET'},{writeHead:(s,h)=>{status=s;headers=h;},end:b=>body=b});assert.equal(status,200);assert.ok(headers['Content-Disposition'].includes(`v${version}.apk`));assert.deepEqual(body,bytes);}for(const path of ['/downloads/secrets.txt','/downloads/federated-copilot-v6.apk?file=secret','/downloads/federated-copilot-v10.apk'])assert.throws(()=>apkHandler(bytes,100,()=>0,path));});
