import {lstatSync,readFileSync,openSync,closeSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {operator} from './common.mjs';
import {protect,custody} from './tool-custody.mjs';
import {validateRecord,mount} from './tool-secrets.mjs';
let lockFd;const lock=resolve(custody,'verification.lock');
try{
 if(process.argv.length!==4||process.argv[2]!=='--expected-version'||! /^(0|[1-9][0-9]{0,8})$/.test(process.argv[3]))throw Error();
 protect();lockFd=openSync(lock,'wx',0o600);const path=resolve(custody,'enrollment.json'),s=lstatSync(path);
 if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>300000)throw Error();
 const record=JSON.parse(readFileSync(path,'utf8'));validateRecord(record);
 const r=await operator('/'+mount+'/data/runtime',{method:'POST',body:{options:{cas:Number(process.argv[3])},data:record}});
 console.log(JSON.stringify({stored:true,version:r.data.version,rendererRequired:true,persistentToolStarted:false}));
}catch{console.error('Tool Vault enrollment failed; verify protected enrollment file, custody lock and expected version');process.exitCode=1;}
finally{if(lockFd!==undefined){closeSync(lockFd);rmSync(lock);}}
