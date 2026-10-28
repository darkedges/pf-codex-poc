import { body, json, startServer, str } from '../lib/http.ts';
import { AuthError, signJwt, verifyJwt, localKey } from '../lib/jwt.ts';
import { authorise, grantFor, type Mode } from '../lib/policy.ts';
const privateKey=localKey('pf-a','private');
const publicKey=localKey('pf-a','public');
const delegationPublic=localKey('delegation','public');
const issuer='http://pf-a.demo.local';
startServer(9201,async(req,res)=>{
  if(req.method==='POST' && req.url==='/dev/issue'){
    const b=await body(req);const kind=str(b,'kind');
    if(kind!=='user' && kind!=='agent') throw new AuthError('Invalid kind');
    const sub=kind==='user'?'partner-a:user-123':'partner-a:agent-research';
    json(res,200,{access_token:signJwt({iss:issuer,sub,aud:'gateway-1',token_class:kind},privateKey,'pf-a',300)});return;
  }
  if(req.method==='POST' && req.url==='/as/token.oauth2'){
    const b=await body(req);
    if(b.grant_type!=='urn:ietf:params:oauth:grant-type:token-exchange' || b.client_id!=='gateway-1-token-exchange' || b.audience!=='api://gateway-2')throw new AuthError('Disallowed exchange client/grant/audience');
    const grantId=str(b,'grant_id');const mode=str(b,'execution_mode') as Mode;
    if(mode!=='interactive' && mode!=='autonomous') throw new AuthError('Invalid mode');
    const actor=verifyJwt(str(b,'actor_token'),publicKey,{issuer,audience:'gateway-1'});
    if(actor.token_class!=='agent')throw new AuthError('Not an agent token');
    const expectedSubjectAudience=mode==='autonomous'?'pf-a:delegation':'gateway-1';
    const subjectIssuer=mode==='autonomous'?'http://delegation.demo.local':issuer;
    const subjectKey=mode==='autonomous'?delegationPublic:publicKey;
    const subject=verifyJwt(str(b,'subject_token'),subjectKey,{issuer:subjectIssuer,audience:expectedSubjectAudience});
    if(mode==='interactive' && subject.token_class!=='user')throw new AuthError('Invalid interactive user proof');
    if(mode==='autonomous' && (subject.grant_id!==grantId || subject.agent!==actor.sub || subject.mode!=='autonomous'))throw new AuthError('Invalid delegation assertion');
    const g=authorise({grantId,user:String(subject.sub),agent:String(actor.sub),mode,scope:'copilot.invoke',resource:'sharepoint:approved-research'});
    const token=signJwt({iss:issuer,sub:g.user,aud:'api://gateway-2',act:{iss:issuer,sub:g.agent},org_id:g.org,delegation_id:g.id,execution_mode:mode,scope:'copilot.invoke'},privateKey,'pf-a',120);
    json(res,200,{access_token:token,issued_token_type:'urn:ietf:params:oauth:token-type:access_token',token_type:'Bearer',expires_in:120});return;
  }
  json(res,404,{error:'Not found'});
});
