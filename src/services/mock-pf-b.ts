import { body, json, startServer, str } from '../lib/http.ts';
import { AuthError, signJwt, verifyJwt, localKey } from '../lib/jwt.ts';
import { authorise, type Mode } from '../lib/policy.ts';
const issuer='http://pf-b.demo.local';
startServer(9202,async(req,res)=>{
  if(req.method==='POST' && req.url==='/as/token.oauth2'){
    const b=await body(req);
    if(b.grant_type!=='urn:ietf:params:oauth:grant-type:token-exchange' || b.client_id!=='gateway-2-token-exchange' || b.audience!=='api://copilot-broker')throw new AuthError('Disallowed exchange client/grant/audience');
    const incoming=verifyJwt(str(b,'subject_token'),localKey('pf-a','public'),{issuer:'http://pf-a.demo.local',audience:'api://gateway-2',requireActor:true});
    const actor=(incoming.act as Record<string,unknown>);
    if(actor.iss!=='http://pf-a.demo.local'||incoming.scope!=='copilot.invoke')throw new AuthError('Invalid actor or scope');
    const grantId=String(incoming.delegation_id);
    const mode=String(incoming.execution_mode) as Mode;
    authorise({grantId,user:String(incoming.sub),agent:String(actor.sub),mode,scope:'copilot.invoke',resource:'sharepoint:approved-research'});
    const token=signJwt({iss:issuer,sub:incoming.sub,aud:'api://copilot-broker',act:incoming.act,org_id:incoming.org_id,delegation_id:grantId,execution_mode:mode,scope:'copilot.invoke',source_iss:incoming.iss},localKey('pf-b','private'),'pf-b',120);
    json(res,200,{access_token:token,issued_token_type:'urn:ietf:params:oauth:token-type:access_token',token_type:'Bearer',expires_in:120});return;
  }
  json(res,404,{error:'Not found'});
});
