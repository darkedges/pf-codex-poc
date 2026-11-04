import {DatabaseSync} from 'node:sqlite';
import {lstatSync,realpathSync} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';
import {PolicyStore} from '../policy/store.ts';
import {PolicyError,type Capability} from '../policy/contracts.ts';
import {recoverPortalGrants} from './portal-recovery.ts';
import type {PortalRecoveryIntent} from './portal-journal.ts';

// Privileged single-host controller operation, never a web route. The service
// supplies its fixed database path; only provenance checked by recoverPortalGrants
// can reach the local revocation writer. No fixture or missing DB fallback.
export async function recoverPortalPolicyDatabase(options:{database:string;journal:{recoveryIntents():PortalRecoveryIntent[];markRecovered(attempt:string):void};capability:Capability;workerStopped?:boolean}){
 let reader:DatabaseSync|undefined,writer:PolicyStore|undefined;
 try{
  const file=lstatSync(options.database),canonical=realpathSync(options.database),expected=resolve(options.database);
  if(!isAbsolute(options.database)||!file.isFile()||file.isSymbolicLink()||file.nlink!==1||(process.platform==='win32'?canonical.toLowerCase()!==expected.toLowerCase():canonical!==expected))throw Error();
  reader=new DatabaseSync(options.database,{readOnly:true,timeout:1000,allowExtension:false});
  if(reader.prepare('PRAGMA user_version').get()?.user_version!==5)throw Error();
  const db=reader;
  const lookup=(id:string)=>{const g=db.prepare('SELECT id,state,recorded_by FROM grants WHERE id=?').get(id);if(!g)throw new PolicyError();return{id:String(g.id),state:String(g.state),recordedBy:String(g.recorded_by)};};
  return await recoverPortalGrants(options.journal,{
   findByTokenHash:async hash=>db.prepare('SELECT c.token_hash,c.grant_id,c.approved_at,g.recorded_by FROM consents c JOIN grants g ON g.id=c.grant_id WHERE c.token_hash=? LIMIT 2').all(hash).map(c=>({tokenHash:String(c.token_hash),grantId:String(c.grant_id),approvedAt:Number(c.approved_at),recordedBy:String(c.recorded_by)})),
   grant:async id=>lookup(id),
   revoke:async id=>{writer??=new PolicyStore(options.database,[options.capability]);writer.revokeGrant(id,'portal-controller-recovery');}
  },{recordedBy:'policy-consent',now:Date.now(),workerStopped:options.workerStopped});
 }catch{throw new PolicyError('unavailable');}
 finally{writer?.close();reader?.close();}
}
