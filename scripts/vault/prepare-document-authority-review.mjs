import {mkdirSync,existsSync,writeFileSync,lstatSync,realpathSync} from 'node:fs';import {resolve} from 'node:path';
import {root} from '../pf/common.mjs';import {custody} from './tool-custody.mjs';import {checkedBytes,digest} from './document-exchange-approval.mjs';import {documentAuthorityFiles} from './document-authority-approval.mjs';
try{
 if(process.argv.length!==2)throw Error();
 const files=Object.fromEntries(documentAuthorityFiles.map(f=>[f,digest(checkedBytes(resolve(root,f)))])),m={schemaVersion:1,purpose:'document-authority-vault-enrollment',approved:false,transitKey:'document-authority',microsoftRequests:0,pfMutations:0,grantAssertionsIssued:0,files};
 const dir=resolve(custody,'document-authority-review');for(const p of [root,resolve(root,'.local'),custody,dir])if(existsSync(p)&&(lstatSync(p).isSymbolicLink()||realpathSync(p).toLowerCase()!==p.toLowerCase()))throw Error();mkdirSync(dir,{recursive:true,mode:0o700});
 const path=resolve(dir,'manifest.json'),raw=JSON.stringify(m,null,2);if(existsSync(path)){if(checkedBytes(path).toString()!==raw)throw Error();}else writeFileSync(path,raw,{mode:0o600,flag:'wx'});
 console.log(JSON.stringify({prepared:true,approved:false,manifestSha256:digest(checkedBytes(path)),filesHashed:documentAuthorityFiles.length,credentialsRead:false,microsoftRequests:0,pfMutations:0}));
}catch{console.error('Document authority review preparation failed; existing packet preserved.');process.exitCode=1;}
