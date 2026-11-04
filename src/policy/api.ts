import { decodeJwt,decodeProtectedHeader,jwtVerify } from 'jose';
import type { TokenVerifier } from '../adapters/token-exchange.ts';
import type { PolicyStore } from './store.ts';
import { PolicyError,type Capability,type Principal,type GrantInput,type VerifiedLogin } from './contracts.ts';
import { bodyHash } from './protocol.ts';
import type { GrantAuthority,AssertionRequest } from '../identity/grant-authority.ts';

export type PolicyCaller={id:string;kid:string;key:CryptoKey;decisionOrigin?:string;previousKeys?:{kid:string;key:CryptoKey}[];roles:('decision'|'grant-admin'|'registry-admin'|'consent'|'authority')[];organisations:string[];agent?:{issuer:string;subject:string;operations:string[]}};
type Input={method:string;path:string;authorization:string;rawBody:string};
type Options={store:PolicyStore;origin:()=>string;callers:PolicyCaller[];verifier:TokenVerifier;authority?:GrantAuthority;loginVerifier?:{verify:(token:string,nonce:string)=>Promise<VerifiedLogin>};consentPolicy?:{agentId:string;capability:Capability;durationsSeconds:number[];modes:string[]};observe?:(event:{event:'policy_request';status:number;durationMs:number})=>void};
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value);
function keys(value:unknown,allowed:string[]){if(!object(value)||Object.keys(value).some(k=>!allowed.includes(k)))throw new PolicyError('invalid_request');}
export class PolicyApi{
  private options:Options;
  constructor(options:Options){
    for(const caller of options.callers)if(caller.decisionOrigin!==undefined){
      try{const u=new URL(caller.decisionOrigin);if(caller.roles.length!==1||caller.roles[0]!=='decision'||u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash||caller.decisionOrigin!==u.origin)throw Error();}catch{throw new PolicyError('configuration');}
    }
    if(!options.callers.length||new Set(options.callers.map(c=>c.id)).size!==options.callers.length||options.callers.some(c=>!c.id||!c.kid||c.key.type!=='public'||!c.organisations.length||!c.roles.length||c.roles.some(r=>!['decision','grant-admin','registry-admin','consent','authority'].includes(r))||(c.roles.includes('consent')&&(!options.loginVerifier||!options.consentPolicy))||(c.roles.includes('authority')&&(!options.authority||!c.agent?.issuer||!c.agent.subject||!c.agent.operations.length))||c.previousKeys?.some(k=>!k.kid||k.key.type!=='public')||new Set([c.kid,...(c.previousKeys??[]).map(k=>k.kid)]).size!==1+(c.previousKeys?.length??0)))throw new PolicyError('configuration');
    this.options={...options,consentPolicy:options.consentPolicy?structuredClone(options.consentPolicy):undefined,callers:options.callers.map(c=>({...c,agent:c.agent?structuredClone(c.agent):undefined,previousKeys:c.previousKeys?.map(k=>({...k})),roles:[...c.roles],organisations:[...c.organisations]}))};
  }
  private async authenticate(input:Input){
    let caller:PolicyCaller,payload:Record<string,unknown>;
    try{
      if(!input.authorization.startsWith('Policy ')||input.authorization.length>8192)throw Error();
      const assertion=input.authorization.slice(7),hint=decodeJwt(assertion),header=decodeProtectedHeader(assertion);
      const known=this.options.callers.find(c=>c.id===hint.iss);
      const key=known&&[known,...(known.previousKeys??[])].find(k=>k.kid===header.kid)?.key;
      if(!known||!key||header.alg!=='RS256'||header.typ!=='policy-request+jwt'||header.jku||header.jwk||header.x5u||header.x5c)throw Error();
      if(known.decisionOrigin&&!['/v1/decisions','/v1/health'].includes(input.path))throw Error();
      const origin=new URL(known.decisionOrigin??this.options.origin());
      if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw Error();
      const result=await jwtVerify(assertion,key,{issuer:known.id,subject:known.id,audience:origin.origin+input.path,algorithms:['RS256'],clockTolerance:5,maxTokenAge:60,requiredClaims:['iss','sub','aud','iat','exp','jti','method','body_sha256']});
      payload=result.payload;
      const now=Math.floor(Date.now()/1000);
      if(payload.aud!==origin.origin+input.path||payload.method!==input.method||payload.body_sha256!==bodyHash(input.rawBody)||typeof payload.jti!=='string'||!Number.isInteger(payload.iat)||!Number.isInteger(payload.exp)||Number(payload.exp)<=now||Number(payload.exp)-Number(payload.iat)>60||Number(payload.exp)<=Number(payload.iat)||Number(payload.iat)>now+5)throw Error();
      caller=known;
    }catch{throw new PolicyError('unauthenticated');}
    this.options.store.consumeAssertion(caller.id,String(payload.jti),Number(payload.exp));
    return caller;
  }
  async handle(input:Input):Promise<{status:number;body:Record<string,unknown>}>{
    const started=Date.now();let response:{status:number;body:Record<string,unknown>};
    try{
      if(input.method!=='POST'||input.path.length>300||!/^\/v1\/[A-Za-z0-9/_:-]+$/.test(input.path))throw new PolicyError('invalid_request');
      if(Buffer.byteLength(input.rawBody)>50000)throw new PolicyError('invalid_request');
      const caller=await this.authenticate(input);
      let body:Record<string,unknown>;
      try{body=JSON.parse(input.rawBody);}catch{throw new PolicyError('invalid_request');}
      if(!object(body))throw new PolicyError('invalid_request');
      const role=(value:PolicyCaller['roles'][number])=>{if(!caller.roles.includes(value))throw new PolicyError();};
      const organisation=(value:unknown)=>{if(typeof value!=='string'||!caller.organisations.includes(value))throw new PolicyError();};
      if(input.path==='/v1/health'){
        role('decision');keys(body,[]);response={status:200,body:{ready:true}};
      }else if(input.path==='/v1/assertions'){
        role('authority');keys(body,['grantId','mode','operation','agentToken','login']);
        if(typeof body.grantId!=='string'||(body.mode!=='interactive'&&body.mode!=='autonomous')||typeof body.agentToken!=='string'||body.agentToken.length>16000||typeof body.operation!=='string')throw new PolicyError('invalid_request');
        if(body.login!==undefined){keys(body.login,['idToken','nonce']);if(typeof(body.login as Record<string,unknown>).idToken!=='string'||typeof(body.login as Record<string,unknown>).nonce!=='string')throw new PolicyError('invalid_request');}
        if(body.mode==='autonomous'&&body.login!==undefined)throw new PolicyError('invalid_request');
        const agent=caller.agent;if(!agent||!agent.operations.includes(body.operation)||!this.options.authority)throw new PolicyError();
        const org=this.options.store.grant(body.grantId)?.organisation;organisation(org);
        const assertion=await this.options.authority.issue(body as AssertionRequest,{issuer:agent.issuer,subject:agent.subject,operation:body.operation,organisation:String(org),workload:caller.id});
        response={status:200,body:{assertion,expiresIn:60}};
      }else if(['/v1/consents/preview','/v1/consents/approve','/v1/consents/revoke'].includes(input.path)){
        role('consent');const policy=this.options.consentPolicy;if(!policy||!this.options.loginVerifier)throw new PolicyError();
        keys(body,input.path.endsWith('/approve')?['idToken','nonce','modes','durationSeconds','termsHash']:input.path.endsWith('/revoke')?['idToken','nonce','grantId']:['idToken','nonce']);
        if(typeof body.idToken!=='string'||body.idToken.length>16000||typeof body.nonce!=='string')throw new PolicyError('invalid_request');
        let login:VerifiedLogin;try{login=await this.options.loginVerifier.verify(body.idToken,body.nonce);}catch{throw new PolicyError();}
        if(input.path.endsWith('/revoke')){
          if(typeof body.grantId!=='string')throw new PolicyError('invalid_request');
          const grant=this.options.store.grant(body.grantId);
          organisation(grant?.organisation);
          this.options.store.revokeOwnedGrant(body.grantId,login,caller.id);response={status:200,body:{revoked:true}};
        }else{
        const options=this.options.store.consentOptions(login,policy.agentId);organisation(options.human.organisation);
        const termsHash=bodyHash(JSON.stringify({version:1,proof:login.tokenHash,...options,capability:policy.capability,modes:policy.modes,durationsSeconds:policy.durationsSeconds}));
        if(input.path.endsWith('/preview'))response={status:200,body:{...options,termsHash,capability:policy.capability,modes:policy.modes,durationsSeconds:policy.durationsSeconds,grants:this.options.store.ownedGrants(login).map(g=>({id:g.id,state:g.state,modes:JSON.parse(String(g.modes)),expiresAt:g.expires_at}))}};
        else if(input.path.endsWith('/approve')){
          if(body.termsHash!==termsHash)throw new PolicyError();
          if(!Array.isArray(body.modes)||body.modes.some(m=>typeof m!=='string'||!policy.modes.includes(m))||typeof body.durationSeconds!=='number'||!policy.durationsSeconds.includes(body.durationSeconds))throw new PolicyError('invalid_request');
          response={status:201,body:this.options.store.createConsentedGrant(login,policy.agentId,body.modes,body.durationSeconds,policy.capability,caller.id,termsHash)};
        }
        }
      }else if(input.path==='/v1/decisions'){
        role('decision');keys(body,['token','capability']);keys(body.capability,['scope','resource']);
        if(typeof body.token!=='string'||body.token.length>16000||typeof(body.capability as Capability).scope!=='string'||typeof(body.capability as Capability).resource!=='string')throw new PolicyError('invalid_request');
        let claims;
        try{claims=await this.options.verifier.verify(body.token);}catch{throw new PolicyError();}
        organisation(claims.org_id);
        const decision=this.options.store.decide(claims,body.capability as Capability,caller.id);
        if(!decision.permit)throw new PolicyError();
        response={status:200,body:{permit:true,decisionId:decision.decisionId,grantVersion:decision.grantVersion}};
      }else if(input.path==='/v1/registry/organisations'){
        role('registry-admin');keys(body,['id']);organisation(body.id);this.options.store.registerOrganisation(String(body.id),caller.id);response={status:201,body:{created:true}};
      }else if(input.path==='/v1/registry/principals'){
        role('registry-admin');keys(body,['id','kind','issuer','subject','organisation','tokenIssuers']);organisation(body.organisation);this.options.store.registerPrincipal(body as Principal,caller.id);response={status:201,body:{created:true}};
      }else if(input.path==='/v1/grants'){
        role('grant-admin');keys(body,['id','humanId','agentId','organisation','modes','scopes','resources','expiresAt','consent']);organisation(body.organisation);keys(body.consent,['reference','approvedAt','expiresAt']);this.options.store.createGrant(body as GrantInput,caller.id);response={status:201,body:{created:true}};
      }else if(/^\/v1\/grants\/[A-Za-z0-9:_-]+\/revoke$/.test(input.path)){
        role('grant-admin');keys(body,[]);const id=input.path.split('/')[3],g=this.options.store.grant(id);organisation(g?.organisation);this.options.store.revokeGrant(id,caller.id);response={status:200,body:{revoked:true}};
      }else if(input.path==='/v1/registry/suspend'){
        role('registry-admin');keys(body,['kind','id']);if(!['organisation','human','agent'].includes(String(body.kind))||typeof body.id!=='string')throw new PolicyError('invalid_request');
        organisation(body.kind==='organisation'?body.id:this.options.store.principal(body.id)?.organisation);
        this.options.store.suspend(body.kind as 'organisation'|'human'|'agent',body.id,caller.id);response={status:200,body:{suspended:true}};
      }else throw new PolicyError('invalid_request');
    }catch(error){
      const code=error instanceof PolicyError?error.code:'unavailable';
      response={status:code==='unauthenticated'?401:code==='invalid_request'?400:code==='forbidden'?403:code==='conflict'?409:503,body:{error:code}};
    }
    try{this.options.observe?.({event:'policy_request',status:response.status,durationMs:Date.now()-started});}catch{}
    return response;
  }
}
