import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { chmodSync } from 'node:fs';
import { PolicyError,type Capability,type Principal,type GrantInput,type PolicyIdentity,type VerifiedLogin } from './contracts.ts';
export {PolicyError} from './contracts.ts';
export type {Capability,Principal,GrantInput,PolicyIdentity} from './contracts.ts';
const id=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9:_-]{1,160}$/.test(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=2048&&!/[\r\n]/.test(v);
const https=(v:string)=>{const u=new URL(v);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search)throw new PolicyError('invalid_request');};
const list=(v:unknown):v is string[]=>Array.isArray(v)&&v.length>0&&v.length<=32&&v.every(text)&&new Set(v).size===v.length;
type LoginBinding={issuer:string;subject:string;audience:string;principalId:string};
export type MobileResourceInput={enrollmentId:string;deviceConsentId:string;humanId:string;agentId:string;organisation:string;termsHash:string;mode:'auto'|'manual';expiresAt:number;capabilities:Capability[];workload:string;loginIssuer:string;loginAudience:string;authTime:number};

// Single-host transactional authority. No decision cache and no automatic fixture import.
export class PolicyStore {
  private db:DatabaseSync;
  private capabilities:Capability[];
  private loginBindings:LoginBinding[];
  private consentDurations:number[];
  constructor(path:string,capabilities:Capability[],options:{loginBindings?:LoginBinding[];consentDurationsSeconds?:number[]}={}){
    if(!capabilities.length||capabilities.some(c=>!text(c.scope)||/\s/.test(c.scope)||!text(c.resource)))throw new PolicyError('configuration');
    this.capabilities=structuredClone(capabilities);
    const durations=options.consentDurationsSeconds??[3600,86400];if(!Array.isArray(durations)||!durations.length||durations.length>8||new Set(durations).size!==durations.length||durations.some(d=>!Number.isSafeInteger(d)||d<60||d>86400))throw new PolicyError('configuration');this.consentDurations=[...durations];
    try{const bindings=options.loginBindings??[];if(!Array.isArray(bindings)||bindings.length>8||bindings.some(b=>!b||Object.keys(b).sort().join()!=='audience,issuer,principalId,subject'||!text(b.issuer)||!text(b.subject)||!text(b.audience)||!id(b.principalId))||new Set(bindings.map(b=>JSON.stringify([b.issuer,b.subject,b.audience]))).size!==bindings.length)throw Error();for(const b of bindings)https(b.issuer);this.loginBindings=structuredClone(bindings);}catch{throw new PolicyError('configuration');}
    this.db=new DatabaseSync(path,{timeout:1000,enableForeignKeyConstraints:true,allowExtension:false});
    if(path!==':memory:')chmodSync(path,0o600);
    const version=Number(this.db.prepare('PRAGMA user_version').get()?.user_version);
    if(version>5){this.db.close();throw new PolicyError('configuration');}
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS organisations(id TEXT PRIMARY KEY,status TEXT NOT NULL CHECK(status IN ('active','suspended'))) STRICT;
      CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('human','agent')),issuer TEXT NOT NULL,subject TEXT NOT NULL,organisation TEXT NOT NULL REFERENCES organisations(id),token_issuers TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','suspended')),UNIQUE(kind,issuer,subject)) STRICT;
      CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,human_id TEXT NOT NULL REFERENCES principals(id),agent_id TEXT NOT NULL REFERENCES principals(id),organisation TEXT NOT NULL REFERENCES organisations(id),modes TEXT NOT NULL,scopes TEXT NOT NULL,resources TEXT NOT NULL,expires_at INTEGER NOT NULL,consent_reference TEXT NOT NULL,approved_at INTEGER NOT NULL,consent_expires_at INTEGER NOT NULL,approved_by TEXT NOT NULL,recorded_by TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoked')),version INTEGER NOT NULL DEFAULT 1) STRICT;
      CREATE TABLE IF NOT EXISTS assertions(caller TEXT NOT NULL,jti TEXT NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(caller,jti)) STRICT;
      CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,at INTEGER NOT NULL,action TEXT NOT NULL,workload TEXT NOT NULL,outcome TEXT NOT NULL,reason TEXT NOT NULL,grant_id TEXT,subject TEXT,actor TEXT,organisation TEXT,mode TEXT,scope TEXT,resource TEXT) STRICT;
      CREATE TABLE IF NOT EXISTS consents(id TEXT PRIMARY KEY,grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id),token_hash TEXT NOT NULL UNIQUE,nonce_hash TEXT NOT NULL,issuer TEXT NOT NULL,subject TEXT NOT NULL,audience TEXT NOT NULL,auth_time INTEGER NOT NULL,approved_at INTEGER NOT NULL,expires_at INTEGER NOT NULL) STRICT;
      `);
    this.transaction(()=>{
      if(!this.db.prepare('PRAGMA table_info(audit)').all().some(c=>c.name==='grant_version'))this.db.exec('ALTER TABLE audit ADD COLUMN grant_version INTEGER');
      const columns=this.db.prepare('PRAGMA table_info(audit)').all();
      for(const column of ['token_issuer','audience','actor_issuer'])if(!columns.some(c=>c.name===column))this.db.exec(`ALTER TABLE audit ADD COLUMN ${column} TEXT`);
      if(version===1)this.db.exec('UPDATE grants SET approved_by=recorded_by');
      if(!this.db.prepare('PRAGMA table_info(consents)').all().some(c=>c.name==='terms_hash'))this.db.exec('ALTER TABLE consents ADD COLUMN terms_hash TEXT');
      this.db.exec('PRAGMA user_version=5');
    });
  }
  close(){this.db.close();}
  // Explicit mobile extension only. Default stores keep schema/version 5 untouched.
  prepareMobileResources(profileHash:string){
    if(!/^[-_A-Za-z0-9]{43}$/.test(profileHash))throw new PolicyError('configuration');
    this.transaction(()=>{
      const exists=this.db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name='mobile_resource_meta'").get();
      if(exists){this.mobileProfile(profileHash);return;}
      if(this.db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name IN ('mobile_resource_consents','mobile_resource_bindings')").get())throw new PolicyError('configuration');
      this.db.exec(`CREATE TABLE mobile_resource_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),profile_hash TEXT NOT NULL) STRICT;
        CREATE TABLE mobile_resource_consents(id TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL,device_consent_id TEXT NOT NULL,human_id TEXT NOT NULL REFERENCES principals(id),agent_id TEXT NOT NULL REFERENCES principals(id),organisation TEXT NOT NULL REFERENCES organisations(id),terms_hash TEXT NOT NULL,mode TEXT NOT NULL,approved_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoked')),login_issuer TEXT NOT NULL,login_audience TEXT NOT NULL,auth_time INTEGER NOT NULL,UNIQUE(enrollment_id,device_consent_id)) STRICT;
        CREATE TABLE mobile_resource_bindings(consent_id TEXT NOT NULL REFERENCES mobile_resource_consents(id),scope TEXT NOT NULL,resource TEXT NOT NULL,grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id),grant_version INTEGER NOT NULL,PRIMARY KEY(consent_id,scope,resource)) STRICT;`);
      this.db.prepare('INSERT INTO mobile_resource_meta VALUES(1,1,?)').run(profileHash);
    });
  }
  private mobileProfile(hash:string){const r=this.db.prepare('SELECT version,profile_hash FROM mobile_resource_meta WHERE id=1').get();if(r?.version!==1||r?.profile_hash!==hash)throw new PolicyError('configuration');}
  mobileResourceBundle(profileHash:string,enrollmentId:string,deviceConsentId:string){
    this.mobileProfile(profileHash);
    const consent=this.db.prepare('SELECT * FROM mobile_resource_consents WHERE enrollment_id=? AND device_consent_id=?').get(enrollmentId,deviceConsentId);
    if(!consent)return undefined;
    const grants=this.db.prepare('SELECT scope,resource,grant_id,grant_version FROM mobile_resource_bindings WHERE consent_id=? ORDER BY scope,resource').all(String(consent.id));
    return{consent,grants};
  }
  private mobileResourceInput(input:MobileResourceInput,requireActive=true){
    const now=Date.now(),human=this.principal(input.humanId),agent=this.principal(input.agentId);
    if(!id(input.enrollmentId)||!id(input.deviceConsentId)||!id(input.workload)||!/^[-_A-Za-z0-9]{43}$/.test(input.termsHash)||!['auto','manual'].includes(input.mode)||!Number.isSafeInteger(input.expiresAt)||input.expiresAt<=0||requireActive&&input.expiresAt<=now||input.expiresAt>now+30*86400000||!text(input.loginIssuer)||!text(input.loginAudience)||!Number.isSafeInteger(input.authTime)||input.authTime>now+5000||!input.capabilities.length||input.capabilities.length>16||new Set(input.capabilities.map(c=>JSON.stringify([c.scope,c.resource]))).size!==input.capabilities.length||input.capabilities.some(c=>!this.capabilities.some(allowed=>allowed.scope===c.scope&&allowed.resource===c.resource))||!human||human.kind!=='human'||human.organisation!==input.organisation||!agent||agent.kind!=='agent'||agent.organisation!==input.organisation||requireActive&&(human.status!=='active'||agent.status!=='active'||this.organisation(input.organisation)?.status!=='active'))throw new PolicyError();
    https(input.loginIssuer);
  }
  approveMobileResources(profileHash:string,input:MobileResourceInput){
    return this.transaction(()=>{
      this.mobileProfile(profileHash);this.mobileResourceInput(input);
      const old=this.mobileResourceBundle(profileHash,input.enrollmentId,input.deviceConsentId);
      if(old){
        if(old.consent.state!=='active'||old.consent.human_id!==input.humanId||old.consent.agent_id!==input.agentId||old.consent.organisation!==input.organisation||old.consent.terms_hash!==input.termsHash||Number(old.consent.expires_at)!==input.expiresAt)throw new PolicyError();
        if(old.grants.length!==input.capabilities.length||old.grants.some(b=>{const g=this.grant(String(b.grant_id));return !g||g.state!=='active'||g.version!==b.grant_version||!input.capabilities.some(c=>c.scope===b.scope&&c.resource===b.resource);}))throw new PolicyError();return old;
      }
      const count=this.db.prepare('SELECT COUNT(*) AS n FROM mobile_resource_consents').get();if(Number(count?.n)>=256)throw new PolicyError('unavailable');
      const consentId='mobile-resource-'+randomUUID(),now=Date.now();
      this.db.prepare('INSERT INTO mobile_resource_consents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(consentId,input.enrollmentId,input.deviceConsentId,input.humanId,input.agentId,input.organisation,input.termsHash,input.mode,now,input.expiresAt,'active',input.loginIssuer,input.loginAudience,input.authTime);
      for(const c of input.capabilities){
        const grantId=randomUUID();this.createGrant({id:grantId,humanId:input.humanId,agentId:input.agentId,organisation:input.organisation,modes:['interactive'],scopes:[c.scope],resources:[c.resource],expiresAt:input.expiresAt,consent:{reference:consentId,approvedAt:now,expiresAt:input.expiresAt}},input.workload);
        this.db.prepare('INSERT INTO mobile_resource_bindings VALUES(?,?,?,?,1)').run(consentId,c.scope,c.resource,grantId);
        this.record('mobile.consent.approve',input.workload,'permit','device_resource_consent',{grantId,subject:this.principal(input.humanId)?.subject,actor:this.principal(input.agentId)?.subject,actorIssuer:this.principal(input.agentId)?.issuer,organisation:input.organisation,mode:'interactive',scope:c.scope,resource:c.resource,grantVersion:1,tokenIssuer:input.loginIssuer,audience:input.loginAudience});
      }
      return this.mobileResourceBundle(profileHash,input.enrollmentId,input.deviceConsentId)!;
    });
  }
  revokeMobileResources(profileHash:string,input:MobileResourceInput){
    this.transaction(()=>{
      this.mobileProfile(profileHash);this.mobileResourceInput(input,false);let bundle=this.mobileResourceBundle(profileHash,input.enrollmentId,input.deviceConsentId);
      if(!bundle){
        const count=this.db.prepare('SELECT COUNT(*) AS n FROM mobile_resource_consents').get();if(Number(count?.n)>=256)throw new PolicyError('unavailable');
        this.db.prepare('INSERT INTO mobile_resource_consents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run('mobile-resource-'+randomUUID(),input.enrollmentId,input.deviceConsentId,input.humanId,input.agentId,input.organisation,input.termsHash,input.mode,Date.now(),input.expiresAt,'revoked',input.loginIssuer,input.loginAudience,input.authTime);
        this.record('mobile.consent.revoke',input.workload,'permit','resource_consent_tombstone',{subject:this.principal(input.humanId)?.subject,actor:this.principal(input.agentId)?.subject,actorIssuer:this.principal(input.agentId)?.issuer,organisation:input.organisation,mode:'interactive',tokenIssuer:input.loginIssuer,audience:input.loginAudience});return;
      }
      if(bundle.consent.human_id!==input.humanId||bundle.consent.agent_id!==input.agentId||bundle.consent.organisation!==input.organisation||bundle.consent.terms_hash!==input.termsHash)throw new PolicyError();
      for(const binding of bundle.grants){const g=this.grant(String(binding.grant_id));if(!g||g.human_id!==input.humanId||g.agent_id!==input.agentId||g.consent_reference!==bundle.consent.id)throw new PolicyError();this.revokeGrant(String(g.id),input.workload);}
      this.db.prepare("UPDATE mobile_resource_consents SET state='revoked' WHERE id=?").run(String(bundle.consent.id));
      this.record('mobile.consent.revoke',input.workload,'permit','device_resource_consent',{subject:this.principal(input.humanId)?.subject,actor:this.principal(input.agentId)?.subject,actorIssuer:this.principal(input.agentId)?.issuer,organisation:input.organisation,mode:'interactive',tokenIssuer:input.loginIssuer,audience:input.loginAudience});
    });
  }
  private transaction<T>(fn:()=>T):T{
    if(this.db.isTransaction)return fn();
    this.db.exec('BEGIN IMMEDIATE');
    try{const result=fn();this.db.exec('COMMIT');return result;}catch(error){this.db.exec('ROLLBACK');throw error;}
  }
  private record(action:string,workload:string,outcome:string,reason='',data:Record<string,unknown>={}){
    if(!id(workload))throw new PolicyError('invalid_request');
    const eventId=randomUUID();
    this.db.prepare('INSERT INTO audit(id,at,action,workload,outcome,reason,grant_id,subject,actor,organisation,mode,scope,resource,grant_version,token_issuer,audience,actor_issuer) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(eventId,Date.now(),action,workload,outcome,reason,
      data.grantId??null,data.subject??null,data.actor??null,data.organisation??null,data.mode??null,data.scope??null,data.resource??null,data.grantVersion??null,data.tokenIssuer??null,data.audience??null,data.actorIssuer??null);
    return eventId;
  }
  organisation(idValue:string){return this.db.prepare('SELECT id,status FROM organisations WHERE id=?').get(idValue);}
  principal(idValue:string){return this.db.prepare('SELECT * FROM principals WHERE id=?').get(idValue);}
  grant(idValue:string){return this.db.prepare('SELECT * FROM grants WHERE id=?').get(idValue);}
  consentForGrant(grantId:string){return this.db.prepare('SELECT * FROM consents WHERE grant_id=?').get(grantId);}
  private authenticatedHuman(login:VerifiedLogin){
    const now=Date.now();
    if(!login||!text(login.issuer)||!text(login.subject)||!text(login.audience)||!Number.isSafeInteger(login.expiresAt)||login.expiresAt<=now||!Number.isSafeInteger(login.issuedAt)||login.issuedAt>now+5000||login.issuedAt<now-300000||!Number.isSafeInteger(login.authTime)||login.authTime>now+5000||login.authTime<now-300000||!/^[-_A-Za-z0-9]{43}$/.test(login.tokenHash)||!/^[-_A-Za-z0-9]{43}$/.test(login.nonceHash))throw new PolicyError();
    const direct=this.db.prepare("SELECT * FROM principals WHERE kind='human' AND issuer=? AND subject=?").get(login.issuer,login.subject);
    const binding=this.loginBindings.find(b=>b.issuer===login.issuer&&b.subject===login.subject&&b.audience===login.audience);
    const bound=binding?this.principal(binding.principalId):undefined;
    if(binding&&(!bound||bound.kind!=='human'||bound.subject!==login.subject||direct&&direct.id!==bound.id))throw new PolicyError();
    const human=binding?bound:direct;
    if(!human||human.status!=='active'||this.organisation(String(human.organisation))?.status!=='active')throw new PolicyError();return human;
  }
  consentOptions(login:VerifiedLogin,agentId:string){
    const human=this.authenticatedHuman(login),agent=this.principal(agentId);
    if(!agent||agent.kind!=='agent'||agent.status!=='active'||agent.organisation!==human.organisation)throw new PolicyError();
    return{human:{subject:human.subject,organisation:human.organisation},agent:{id:agent.id,subject:agent.subject,issuer:agent.issuer}};
  }
  ownedGrants(login:VerifiedLogin){
    const human=this.authenticatedHuman(login);
    return this.db.prepare('SELECT id,state,modes,expires_at FROM grants WHERE human_id=? ORDER BY rowid DESC LIMIT 20').all(String(human.id));
  }
  createConsentedGrant(login:VerifiedLogin,agentId:string,modes:string[],durationSeconds:number,capability:Capability,workload:string,termsHash?:string){
    return this.transaction(()=>{
      const human=this.authenticatedHuman(login);this.consentOptions(login,agentId);
      if(!this.consentDurations.includes(durationSeconds)||!list(modes)||!modes.includes('interactive')||modes.some(m=>!['interactive','autonomous'].includes(m)))throw new PolicyError('invalid_request');
      if(this.db.prepare('SELECT id FROM consents WHERE token_hash=?').get(login.tokenHash))throw new PolicyError('conflict');
      const grantId=randomUUID(),consentId='consent-'+randomUUID(),approvedAt=Date.now(),expiresAt=approvedAt+durationSeconds*1000;
      this.createGrant({id:grantId,humanId:String(human.id),agentId,organisation:String(human.organisation),modes,scopes:[capability.scope],resources:[capability.resource],expiresAt,consent:{reference:consentId,approvedAt,expiresAt}},workload);
      if(termsHash!==undefined&&!/^[-_A-Za-z0-9]{43}$/.test(termsHash))throw new PolicyError('invalid_request');
      this.db.prepare('INSERT INTO consents VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(consentId,grantId,login.tokenHash,login.nonceHash,login.issuer,login.subject,login.audience,login.authTime,approvedAt,expiresAt,termsHash??null);
      this.db.prepare('UPDATE grants SET approved_by=? WHERE id=?').run(login.subject,grantId);
      this.record('consent.approve',workload,'permit','authenticated_human',{grantId,subject:human.subject,organisation:human.organisation,actor:this.principal(agentId)?.subject,actorIssuer:this.principal(agentId)?.issuer,tokenIssuer:login.issuer,audience:login.audience,scope:capability.scope,resource:capability.resource,grantVersion:1});
      return{grantId,expiresAt,modes:[...modes]};
    });
  }
  revokeOwnedGrant(grantId:string,login:VerifiedLogin,workload:string){
    this.transaction(()=>{const human=this.authenticatedHuman(login),grant=this.grant(grantId);if(!grant||grant.human_id!==human.id)throw new PolicyError();this.revokeGrant(grantId,workload);});
  }
  authoriseConsentedGrant(grantId:string,actor:{issuer:string;subject:string},mode:string,capability:Capability,workload:string,login?:VerifiedLogin){
    return this.transaction(()=>{
      const g=this.grant(grantId),evidence=this.consentForGrant(grantId),human=g?this.principal(String(g.human_id)):undefined,agent=g?this.principal(String(g.agent_id)):undefined;
      if(!g||!evidence||!human||!agent||g.state!=='active'||Number(g.expires_at)<=Date.now()||Number(g.consent_expires_at)<=Date.now()||human.status!=='active'||agent.status!=='active'||this.organisation(String(g.organisation))?.status!=='active'||actor.issuer!==agent.issuer||actor.subject!==agent.subject||!['interactive','autonomous'].includes(mode)||!JSON.parse(String(g.modes)).includes(mode)||!JSON.parse(String(g.scopes)).includes(capability.scope)||!JSON.parse(String(g.resources)).includes(capability.resource)||!this.capabilities.some(c=>c.scope===capability.scope&&c.resource===capability.resource))throw new PolicyError();
      if(mode==='interactive'&&(!login||this.authenticatedHuman(login).id!==human.id))throw new PolicyError();
      this.record('authority.issue',workload,'permit','consented_grant',{grantId,subject:human.subject,actor:agent.subject,actorIssuer:agent.issuer,organisation:g.organisation,mode,scope:capability.scope,resource:capability.resource,grantVersion:g.version});
      return{sub:String(human.subject),act:{iss:String(agent.issuer),sub:String(agent.subject)},org_id:String(g.organisation),delegation_id:grantId,execution_mode:mode,scope:capability.scope};
    });
  }
  registerOrganisation(value:string,workload:string){
    if(!id(value))throw new PolicyError('invalid_request');
    this.transaction(()=>{if(this.organisation(value))throw new PolicyError('conflict');this.db.prepare("INSERT INTO organisations VALUES(?,'active')").run(value);this.record('organisation.create',workload,'permit','',{organisation:value});});
  }
  registerPrincipal(p:Principal,workload:string){
    if(!p||!id(p.id)||!['human','agent'].includes(p.kind)||!text(p.subject)||!id(p.organisation))throw new PolicyError('invalid_request');
    https(p.issuer);
    if(p.kind==='human'){if(!list(p.tokenIssuers))throw new PolicyError('invalid_request');p.tokenIssuers.forEach(https);}
    this.transaction(()=>{
      if(this.organisation(p.organisation)?.status!=='active')throw new PolicyError();
      if(this.principal(p.id)||this.db.prepare('SELECT id FROM principals WHERE kind=? AND issuer=? AND subject=?').get(p.kind,p.issuer,p.subject))throw new PolicyError('conflict');
      this.db.prepare("INSERT INTO principals VALUES(?,?,?,?,?,?,'active')").run(p.id,p.kind,p.issuer,p.subject,p.organisation,JSON.stringify(p.tokenIssuers??[]));
      this.record('principal.create',workload,'permit','',{organisation:p.organisation,...(p.kind==='human'?{subject:p.subject}:{actor:p.subject})});
    });
  }
  createGrant(g:GrantInput,workload:string){
    const now=Date.now();
    if(!g||!id(g.id)||!id(g.humanId)||!id(g.agentId)||!id(g.organisation)||!list(g.modes)||g.modes.some(m=>!['interactive','autonomous'].includes(m))||
      !list(g.scopes)||!list(g.resources)||g.scopes.some(s=>!this.capabilities.some(c=>c.scope===s))||g.resources.some(r=>!this.capabilities.some(c=>c.resource===r))||
      !Number.isSafeInteger(g.expiresAt)||g.expiresAt<=now||g.expiresAt>now+30*86400000||!g.consent||!id(g.consent.reference)||
      !Number.isSafeInteger(g.consent.approvedAt)||g.consent.approvedAt<=0||g.consent.approvedAt>now+5000||!Number.isSafeInteger(g.consent.expiresAt)||g.consent.expiresAt<g.expiresAt)throw new PolicyError('invalid_request');
    this.transaction(()=>{
      if(this.grant(g.id))throw new PolicyError('conflict');
      const human=this.principal(g.humanId),agent=this.principal(g.agentId);
      if(this.organisation(g.organisation)?.status!=='active'||!human||human.kind!=='human'||human.status!=='active'||human.organisation!==g.organisation||
        !agent||agent.kind!=='agent'||agent.status!=='active'||agent.organisation!==g.organisation)throw new PolicyError();
      this.db.prepare("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'active',1)").run(g.id,g.humanId,g.agentId,g.organisation,JSON.stringify(g.modes),JSON.stringify(g.scopes),JSON.stringify(g.resources),g.expiresAt,g.consent.reference,g.consent.approvedAt,g.consent.expiresAt,workload,workload);
      this.record('grant.create',workload,'permit','',{grantId:g.id,subject:human.subject,actor:agent.subject,organisation:g.organisation,grantVersion:1});
    });
  }
  revokeGrant(grantId:string,workload:string){
    if(!id(grantId))throw new PolicyError('invalid_request');
    this.transaction(()=>{const g=this.grant(grantId);if(!g)throw new PolicyError();
      this.db.prepare("UPDATE grants SET state='revoked',version=version+1 WHERE id=? AND state='active'").run(grantId);
      this.record('grant.revoke',workload,'permit','',{grantId,organisation:g.organisation,grantVersion:this.grant(grantId)?.version});});
  }
  suspend(kind:'organisation'|'human'|'agent',value:string,workload:string){
    if(!id(value)||!['organisation','human','agent'].includes(kind))throw new PolicyError('invalid_request');
    this.transaction(()=>{
      const result=kind==='organisation'?this.db.prepare("UPDATE organisations SET status='suspended' WHERE id=?").run(value):this.db.prepare("UPDATE principals SET status='suspended' WHERE id=? AND kind=?").run(value,kind);
      if(result.changes!==1)throw new PolicyError();this.record(`${kind}.suspend`,workload,'permit');
    });
  }
  decide(claims:PolicyIdentity,capability:Capability,workload:string){
    return this.transaction(()=>{
      const g=typeof claims?.delegation_id==='string'?this.grant(claims.delegation_id):undefined;
      const human=g?this.principal(String(g.human_id)):undefined,agent=g?this.principal(String(g.agent_id)):undefined;
      let reason='binding';
      const binding=g&&human&&agent&&claims.sub===human.subject&&claims.act?.sub===agent.subject&&claims.act?.iss===agent.issuer&&
        claims.org_id===g.organisation&&human.organisation===g.organisation&&agent.organisation===g.organisation&&JSON.parse(String(human.token_issuers)).includes(claims.iss);
      let permit=false;
      if(binding){
        if(g.state!=='active'||Number(g.expires_at)<=Date.now()||Number(g.consent_expires_at)<=Date.now())reason='grant_inactive';
        else if(human.status!=='active'||agent.status!=='active'||this.organisation(String(g.organisation))?.status!=='active')reason='principal_inactive';
        else if(!this.capabilities.some(c=>c.scope===capability?.scope&&c.resource===capability?.resource)||claims.scope!==capability.scope||!JSON.parse(String(g.scopes)).includes(capability.scope)||!JSON.parse(String(g.resources)).includes(capability.resource)||!JSON.parse(String(g.modes)).includes(claims.execution_mode))reason='capability';
        else{permit=true;reason='active_grant';}
      }
      const decisionId=this.record('decision',workload,permit?'permit':'deny',reason,{grantId:g?.id,subject:human?.subject,actor:agent?.subject,organisation:g?.organisation,grantVersion:g?.version,actorIssuer:agent?.issuer,
        tokenIssuer:human&&JSON.parse(String(human.token_issuers)).includes(claims?.iss)?claims.iss:null,audience:text(claims?.aud)?claims.aud:null,
        mode:['interactive','autonomous'].includes(claims?.execution_mode)?claims.execution_mode:null,
        scope:this.capabilities.find(c=>c.scope===capability?.scope)?.scope,resource:this.capabilities.find(c=>c.resource===capability?.resource)?.resource});
      return{permit,decisionId,reason,grantVersion:g?.version??null};
    });
  }
  consumeAssertion(caller:string,jti:string,exp:number){
    this.consumeBoundAssertion(caller,jti,exp,65);
  }
  // Only the explicitly deployed minute-lifetime mobile profile uses this
  // window. Generic policy/client assertions retain their one-minute bound.
  consumeMobileAssertion(caller:string,jti:string,exp:number){
    if(!['mobile-chat-authority','mobile-document-authority','mobile-chat-exchange','mobile-document-exchange'].includes(caller))throw new PolicyError('unauthenticated');
    this.consumeBoundAssertion(caller,jti,exp,185);
  }
  private consumeBoundAssertion(caller:string,jti:string,exp:number,maximum:number){
    if(!id(caller)||!id(jti)||!Number.isInteger(exp)||exp<=Math.floor(Date.now()/1000)||exp>Math.floor(Date.now()/1000)+maximum)throw new PolicyError('unauthenticated');
    this.transaction(()=>{this.db.prepare('DELETE FROM assertions WHERE expires_at<=?').run(Math.floor(Date.now()/1000));
      try{this.db.prepare('INSERT INTO assertions VALUES(?,?,?)').run(caller,jti,exp);}catch{throw new PolicyError('unauthenticated');}});
  }
  audit(){return this.db.prepare('SELECT * FROM audit ORDER BY rowid').all();}
  // The mobile host owns only these audit producers. Never delete grants,
  // consent/replay metadata or another service's historical evidence here.
  pruneMobileAudit(){this.db.prepare("DELETE FROM audit WHERE at<=? AND workload IN ('mobile-resource-consent','mobile-chat-authority','mobile-document-authority','mobile-chat-exchange','mobile-document-exchange')").run(Date.now()-86400000);}
}
