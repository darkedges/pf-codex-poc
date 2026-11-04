import test from 'node:test';import assert from 'node:assert/strict';
import {bindLabProviderIdentity,providerSso} from '../../scripts/copilot/provider-login.ts';
import {profile} from '../../scripts/pf/config.mjs';
const provider=()=>({...providerSso,iss:providerSso.issuer,aud:providerSso.audience,sub:profile.human});
const broker=()=>({sub:profile.human,org_id:profile.org,act:{iss:profile.agentIssuer,sub:profile.agent},execution_mode:'interactive'});
test('explicit lab identity binding is issuer-qualified and never infers organisation or actor from user token',()=>{assert.doesNotThrow(()=>bindLabProviderIdentity(provider() as any,broker() as any));for(const field of ['iss','aud','sub']){const p=provider();p[field]='other';assert.throws(()=>bindLabProviderIdentity(p as any,broker() as any));}for(const change of [b=>b.sub='other',b=>b.org_id='other',b=>b.act.sub='other',b=>b.act.iss='https://other.test',b=>b.execution_mode='autonomous']){const b=broker();change(b);assert.throws(()=>bindLabProviderIdentity(provider() as any,b as any));}});
