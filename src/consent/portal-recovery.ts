import {PolicyError} from '../policy/contracts.ts';
import type {PortalRecoveryIntent} from './portal-journal.ts';
type Journal={recoveryIntents():PortalRecoveryIntent[];markRecovered(attempt:string):void};
type Consent={tokenHash:string;grantId:string;recordedBy:string;approvedAt:number};
export type PortalRecoveryAuthority={
 findByTokenHash(hash:string):Promise<Consent[]>;
 grant(id:string):Promise<{id:string;state:string;recordedBy:string}>;
 revoke(id:string):Promise<void>;
};
// Privileged controller only, after a lease expires or its owned web worker stops.
// This decreases authority; it never refreshes human proof or issues a grant/token.
export async function recoverPortalGrants(journal:Journal,authority:PortalRecoveryAuthority,options:{recordedBy:string;now:number;workerStopped?:boolean}){
 if(!/^[A-Za-z0-9:_-]{1,160}$/.test(options.recordedBy)||!Number.isSafeInteger(options.now)||options.now<=0)throw new PolicyError('configuration');
 let recovered=0,pending=0;
 for(const intent of journal.recoveryIntents()){
  if(!options.workerStopped&&intent.recoverAfter>options.now){pending++;continue;}
  const matches=await authority.findByTokenHash(intent.tokenHash);
  // A delayed remote commit can become visible later. Never forget an intent
  // merely because the approval request timed out or its response was lost.
  if(matches.length===0){pending++;continue;}
  if(matches.length!==1)throw new PolicyError();
  const c=matches[0];
  if(c.tokenHash!==intent.tokenHash||c.recordedBy!==options.recordedBy||!Number.isSafeInteger(c.approvedAt)||c.approvedAt<intent.createdAt||c.approvedAt>options.now||!/^[A-Za-z0-9:_-]{1,160}$/.test(c.grantId)||intent.grantId!==null&&intent.grantId!==c.grantId)throw new PolicyError();
  const g=await authority.grant(c.grantId);
  if(g.id!==c.grantId||g.recordedBy!==options.recordedBy||!['active','revoked'].includes(g.state))throw new PolicyError();
  if(g.state==='active')await authority.revoke(c.grantId);
  const after=await authority.grant(c.grantId);
  if(after.id!==c.grantId||after.recordedBy!==options.recordedBy||after.state!=='revoked')throw new PolicyError('unavailable');
  journal.markRecovered(intent.attempt);recovered++;
 }
 return{recovered,pending};
}
