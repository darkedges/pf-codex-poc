import {PolicyError,type VerifiedLogin} from '../policy/contracts.ts';
import type {PortalExecutionJournal} from './portal-journal-profile.ts';
import type {AgentPortalOptions} from './agent-portal.ts';
type Proof={idToken:string;nonce:string};
type Execution={grantId:string;providerToken:string;login:Proof};
type Options={
 journal:Pick<PortalExecutionJournal,'beginConsent'|'attachGrant'|'finish'|'beginExecution'|'consume'>;
 verifier:{verify(token:string,nonce:string):Promise<VerifiedLogin>};
 policy:{request(path:string,body:Record<string,unknown>):Promise<Record<string,unknown>>};
 perform(proof:Execution,controls:{beforeConversation():void;beforeTokenPost():void}):Promise<{authorized:true}>;
};
// Independent secret-holding controller. No browser receives this journal or
// verifier, and no request may select a policy endpoint outside this closed set.
export function createPortalControlPlane(options:Options):Pick<AgentPortalOptions,'policy'|'execute'>{
 const attempts=new Map<string,{attempt:string;grantId?:string}>();
 const verify=async(proof:Record<string,unknown>)=>{
  if(typeof proof.idToken!=='string'||typeof proof.nonce!=='string')throw new PolicyError();
  return options.verifier.verify(proof.idToken,proof.nonce);
 };
 const owned=async(proof:Proof,grantId:string)=>{
  const login=await verify(proof),record=attempts.get(login.tokenHash);
  if(!record||record.grantId!==grantId)throw new PolicyError();return record;
 };
 return{
  policy:{request:async(path,body)=>{
   if(!['/v1/consents/preview','/v1/consents/approve','/v1/consents/revoke'].includes(path))throw new PolicyError();
   const login=await verify(body);
   if(path.endsWith('/preview'))return options.policy.request(path,body);
   if(path.endsWith('/approve')){
    if(Object.keys(body).some(k=>!['idToken','nonce','termsHash','modes','durationSeconds'].includes(k))||JSON.stringify(body.modes)!=='["interactive"]'||body.durationSeconds!==3600)throw new PolicyError();
    const attempt=options.journal.beginConsent(login.tokenHash);attempts.set(login.tokenHash,{attempt});
    // Persist ownership BEFORE requesting approval. A missing/lost response must
    // retain an obligation that the recovery controller resolves independently.
    const result=await options.policy.request(path,body);
    if(typeof result.grantId!=='string')throw new PolicyError('unavailable');
    options.journal.attachGrant(attempt,result.grantId);attempts.set(login.tokenHash,{attempt,grantId:result.grantId});return result;
   }
   if(typeof body.grantId!=='string')throw new PolicyError();
   const record=await owned({idToken:String(body.idToken),nonce:String(body.nonce)},body.grantId);
   // Recovery independently checks the authority's persisted revoked state
   // before marking the journal entry recovered; an HTTP result alone is not it.
   const result=await options.policy.request(path,body);if(result.revoked!==true)throw new PolicyError('unavailable');options.journal.finish(record.attempt);return result;
  }},
  execute:async(proof)=>{
   const record=await owned(proof.login,proof.grantId);
   options.journal.beginExecution(record.attempt);
   try{
    const result=await options.perform(proof,{beforeConversation:()=>options.journal.consume(record.attempt,'conversation'),beforeTokenPost:()=>options.journal.consume(record.attempt,'tokenPost')});
    if(result?.authorized!==true)throw new PolicyError();
    options.journal.consume(record.attempt,'successfulTool');return{authorized:true};
   }finally{options.journal.finish(record.attempt);}
  }
 };
}
