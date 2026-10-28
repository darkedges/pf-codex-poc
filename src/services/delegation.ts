import { body, json, startServer, str, getBearer } from '../lib/http.ts';
import { verifyJwt, signJwt, localKey, AuthError } from '../lib/jwt.ts';
import { authorise } from '../lib/policy.ts';
const publicA=localKey('pf-a','public');
const privateDelegation=localKey('delegation','private');
startServer(9200,async(req,res)=>{
  if(req.method==='POST' && req.url==='/v1/autonomous-assertion'){
    const actor=verifyJwt(getBearer(req),publicA,{issuer:'http://pf-a.demo.local',audience:'gateway-1'});
    if(actor.token_class!=='agent')throw new AuthError('Not an agent');
    const b=await body(req);const grantId=str(b,'grant_id');
    const g=authorise({grantId,user:str(b,'user'),agent:String(actor.sub),mode:'autonomous',scope:'copilot.invoke',resource:'sharepoint:approved-research'});
    json(res,200,{assertion:signJwt({iss:'http://delegation.demo.local',sub:g.user,aud:'pf-a:delegation',agent:g.agent,grant_id:g.id,mode:'autonomous'},privateDelegation,'delegation',60)});return;
  }
  json(res,404,{error:'Not found'});
});
