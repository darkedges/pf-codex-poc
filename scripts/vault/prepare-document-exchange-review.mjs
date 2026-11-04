import {mkdirSync,existsSync,writeFileSync,readFileSync,lstatSync,realpathSync} from 'node:fs';import {resolve} from 'node:path';
import {root} from '../pf/common.mjs';import {custody} from './tool-custody.mjs';import {documentEnrollmentFiles,checkedBytes,digest} from './document-exchange-approval.mjs';
try{
 if(process.argv.length!==2)throw Error();
 const files=Object.fromEntries(documentEnrollmentFiles.map(f=>[f,digest(checkedBytes(resolve(root,f)))]));
 const m={schemaVersion:1,purpose:'document-exchange-vault-enrollment',approved:false,record:'/federated-copilot-tool-secrets/data/document-exchange',microsoftRequests:0,pfMutations:0,files};
 const dir=resolve(custody,'document-exchange-review');
 for(const p of [root,resolve(root,'.local'),custody,dir])if(existsSync(p)&&(lstatSync(p).isSymbolicLink()||realpathSync(p).toLowerCase()!==p.toLowerCase()))throw Error();
 mkdirSync(dir,{recursive:true,mode:0o700});const path=resolve(dir,'manifest.json'),bytes=JSON.stringify(m,null,2);
 if(existsSync(path)){if(checkedBytes(path).toString()!==bytes)throw Error();}else writeFileSync(path,bytes,{flag:'wx',mode:0o600});
 console.log(JSON.stringify({prepared:true,approved:false,manifestSha256:digest(readFileSync(path)),filesHashed:documentEnrollmentFiles.length,credentialsRead:false,pfMutations:0,microsoftRequests:0}));
}catch{console.error('Document exchange review preparation failed; existing packet preserved.');process.exitCode=1;}
