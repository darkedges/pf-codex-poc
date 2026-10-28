import {body, json, startServer, str, postJson, tokenExchange,envUrl} from '../lib/http.ts';
import {verifyJwt,localKey,AuthError} from '../lib/jwt.ts';
import {authorise,type Mode} from '../lib/policy.ts';
const pfA=envUrl('PF_A_URL','http://127.0.0.1:9201');
const g2=envUrl('GATEWAY_2_URL','http://127.0.0.1:9302');
const delegation=envUrl('DELEGATION_URL','http://127.0.0.1:9200');
startServer(9301,async(req,res)=>{
  if(req.method==='POST' && req.url==='/v1/invoke'){
    const b=await body(req);const mode=str(b,'mode') as Mode;
    if(mode!=='autonomous' && mode!=='interactive')throw new AuthError('Invalid mode');
    const actorJwt=str(b,'agent_token');
    const actor=verifyJwt(actorJwt,localKey('pf-a','public'),{issuer:'http://pf-a.demo.local',audience:'gateway-1'});
    if(actor.token_class!=='agent')throw new AuthError('Invalid agent');
    const grantId=str(b,'grant_id');
    const operation=str(b,'operation');const resource=str(b,'resource');
    let userJwt:string,user:string;
    if(mode==='interactive'){
      userJwt=str(b,'user_token');
      const subject=verifyJwt(userJwt,localKey('pf-a','public'),{issuer:'http://pf-a.demo.local',audience:'gateway-1'});
      if(subject.token_class!=='user') throw new AuthError('Invalid user token');
      user=String(subject.sub);
    } else {
      // Demo user lookup from grant; production MUST use a trusted, persistent grant service.
      user=str(b,'user');
      const proof=await postJson(delegation+'/v1/autonomous-assertion',{grant_id:grantId,user},{Authorization:`Bearer ${actorJwt}`});
      userJwt=str(proof,'assertion');
    }
    // Gateway 1 pre-checks; mock PF A will independently validate them again.
    authorise({grantId,user,agent:String(actor.sub),mode,scope:'copilot.invoke',resource:'sharepoint:approved-research'});
    const token=await tokenExchange(pfA+'/as/token.oauth2',{
      grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:'gateway-1-token-exchange',
      subject_token:userJwt,subject_token_type:mode==='interactive'?'urn:ietf:params:oauth:token-type:access_token':'urn:example:token-type:delegation-assertion',
      actor_token:actorJwt,actor_token_type:'urn:ietf:params:oauth:token-type:access_token',audience:'api://gateway-2',grant_id:grantId,execution_mode:mode
    });
    const output=await postJson(g2+'/v1/ingress',{operation,resource,query:String(b.query||'')},{Authorization:`Bearer ${token}`});
    json(res,200,output);return;
  }
  json(res,404,{error:'Not found'});
});
