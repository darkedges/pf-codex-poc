import {randomUUID} from 'node:crypto';
import {resolve} from 'node:path';
import {vault} from './common.mjs';
import {protect,rendererCertificate,custody} from './tool-custody.mjs';
import {fetchRecord,publishRecord} from './tool-secrets.mjs';
try{
 if(process.argv.length!==2)throw Error();
 protect();const identity=rendererCertificate();
 const {record,version}=await fetchRecord((path,options)=>vault(path,{...options,...identity}));
 const name='snapshot-'+version+'-'+randomUUID();publishRecord(record,resolve(custody,name));
 console.log(JSON.stringify({rendered:true,version,snapshot:name,files:6,persistentToolStarted:false}));
}catch{console.error('Tool Vault render failed; no credential snapshot published');process.exitCode=1;}
