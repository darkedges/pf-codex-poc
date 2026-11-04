import {readFileSync,writeFileSync,readdirSync} from 'node:fs';import {resolve} from 'node:path';import {request} from 'node:https';import {createHash} from 'node:crypto';import {DatabaseSync} from 'node:sqlite';
import {custody,readProtected} from './tool-custody.mjs';import {root} from '../pf/common.mjs';
const directory=resolve(custody,'portal-service'),json=path=>JSON.parse(readFileSync(path,'utf8')),digest=v=>createHash('sha256').update(v).digest('hex');
const budgets=()=>Object.fromEntries(readdirSync(resolve(root,'.local/copilot')).filter(n=>/^live-sso.*budget\.json$/.test(n)).sort().map(n=>[n,digest(readFileSync(resolve(root,'.local/copilot',n)))]));
const grants=()=>{const db=new DatabaseSync(resolve(custody,'policy.sqlite'),{readOnly:true});try{return digest(JSON.stringify(db.prepare('SELECT id,state,version FROM grants ORDER BY id').all()));}finally{db.close();}};
const emptyTrial=()=>{const db=new DatabaseSync(resolve(directory,'journal.sqlite'),{readOnly:true});try{return db.prepare('SELECT COUNT(*) AS count FROM portal_trial').get().count===0&&db.prepare('SELECT COUNT(*) AS count FROM portal_intents').get().count===0;}finally{db.close();}};
const probe=(method,path,headers={},body='')=>new Promise((done,reject)=>{
 const req=request({hostname:'localhost',family:4,servername:'localhost',port:9466,path,method,ca:readProtected('portal-origin-cert.pem'),headers:{Host:'agent.copilot.darkedges.com',...headers}},res=>{let raw='';res.on('data',part=>{raw+=part;if(raw.length>65536)req.destroy();});res.on('error',()=>reject(Error()));res.on('end',()=>done({status:res.statusCode,disabled:raw.includes('Live testing is not enabled'),cors:res.headers['access-control-allow-origin']!==undefined}));});const timer=setTimeout(()=>req.destroy(),5000);req.on('close',()=>clearTimeout(timer));req.on('error',()=>reject(Error()));req.end(body);
});
try{
 if(process.argv.slice(2).join()!=='--verify')throw Error();
 const before=json(resolve(directory,'status.json'));if(before.state!=='ready'||before.mode!=='staged'||before.signInEnabled!==false||Date.now()-Date.parse(before.at)>20000||!emptyTrial())throw Error();
 const history=budgets(),grantState=grants(),expected=json(resolve(custody,'portal-executor-review/approval.json')).historicalBudgetHashes;
 if(Object.keys(history).length!==Object.keys(expected).length||Object.entries(history).some(([k,v])=>expected[k]!==v))throw Error();
 const home=await probe('GET','/');if(home.status!==200||!home.disabled||home.cors)throw Error();
 for(const [method,path,headers,body,status]of [['GET','/admin',{},'',404],['GET','/',{Host:'other.invalid'},'',400],['POST','/login',{'Content-Type':'application/x-www-form-urlencoded',Origin:'https://agent.copilot.darkedges.com'},'csrf=invalid',403],['GET','/',{'X-Agent-Id':'forged'},'',400],['GET','/',{Authorization:'Bearer synthetic-unbound'},'',400]]){const result=await probe(method,path,headers,body);if(result.status!==status)throw Error();}
 if(!emptyTrial()||JSON.stringify(budgets())!==JSON.stringify(history)||grants()!==grantState)throw Error();
 const receipt={verifiedAt:new Date().toISOString(),passed:true,mode:'staged',checks:6,signInEnabled:false,trialRows:0,ownedIntentRows:0,historicalBudgetCount:Object.keys(history).length,historicalBudgetsUnchanged:true,policyGrantStateUnchanged:true,rawCredentialsRetained:false,microsoftRequests:0,publicRoutesChanged:false};writeFileSync(resolve(directory,'stage-verification.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
}catch{console.error('Staged portal verification failed; no Microsoft request or grant was made by this check.');process.exitCode=1;}
