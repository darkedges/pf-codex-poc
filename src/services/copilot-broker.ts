import { body, getBearer, json, startServer, str } from '../lib/http.ts';
import { verifyJwt, localKey, AuthError } from '../lib/jwt.ts';
import { authorise, operationScope,type Mode } from '../lib/policy.ts';
import { randomUUID } from 'node:crypto';
// Mocked resources intentionally do not contain any real customer, SharePoint or Microsoft data.
const mockDocuments=[
  {id:'doc-01',site:'approved-research',name:'Approved research overview',summary:'Example public-safe approved research content'},
  {id:'doc-02',site:'approved-research',name:'Product policy guide',summary:'Example product policy content'}
];
startServer(9400,async(req,res)=>{
  if(req.method==='POST' && req.url==='/v1/execute'){
    const claims=verifyJwt(getBearer(req),localKey('pf-b','public'),{issuer:'http://pf-b.demo.local',audience:'api://copilot-broker',requireActor:true});
    const actor=claims.act as Record<string,unknown>;
    if(actor.iss!=='http://pf-a.demo.local'||claims.scope!=='copilot.invoke')throw new AuthError('Invalid token claims');
    const b=await body(req),operation=str(b,'operation'),resource=str(b,'resource');
    const query=String(b.query||'').slice(0,200);
    const scope=operationScope(operation,resource);
    const grant=authorise({grantId:String(claims.delegation_id),user:String(claims.sub),agent:String(actor.sub),mode:String(claims.execution_mode) as Mode,scope,resource});
    if(process.env.COPILOT_MODE && process.env.COPILOT_MODE!=='mock') throw new AuthError('Real Copilot integration not configured; see docs/copilot-studio.md');
    if(process.env.M365_MODE && process.env.M365_MODE!=='mock') throw new AuthError('Real Entra/Graph adapter not configured; see docs/microsoft365.md');
    const result=operation==='documents.search'
      ? mockDocuments.filter(x=>x.name.toLowerCase().includes(query.toLowerCase())||!query)
      : [{id:'customer-123',name:'Example customer (synthetic)',readOnly:true}];
    // This is a SIMULATED Copilot+M365 path, not an actual Direct Line or Graph call.
    json(res,200,{simulation:true,operation,resource,results:result,identity:{subject:claims.sub,actor:actor.sub,organisation:grant.org,delegation_id:grant.id,execution_mode:claims.execution_mode},authorisation:{policy:'default-deny',scope,decision:'permit'},trace_id:randomUUID()});return;
  }
  json(res,404,{error:'Not found'});
});
