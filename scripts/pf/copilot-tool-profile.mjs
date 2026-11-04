import {copilotProfile} from './copilot-config.mjs';
import {profile} from './config.mjs';
import {nodes} from './common.mjs';
export function toolPolicyEnabled(env){
 if(env.POLICY_COPILOT_TOOL_PROFILE===undefined)return false;
 if(env.POLICY_COPILOT_TOOL_PROFILE!=='local-verified'||typeof env.POLICY_DATABASE!=='string'||!env.POLICY_DATABASE)throw Error('Explicit local tool policy profile and isolated policy database required');
 return true;
}
export function toolTrust(){return{issuer:copilotProfile.toolIssuer,jwksUri:nodes.b.issuer+'/pf/JWKS',audience:copilotProfile.toolAudience,algorithms:['RS256'],keyIds:['copilot-tool-signing'],organisations:[profile.org],actorIssuers:[profile.agentIssuer],maxLifetimeSeconds:120};}
export function toolExchangeConfig(){return{
 upstream:[{...toolTrust(),issuer:nodes.a.issuer,jwksUri:nodes.a.issuer+'/pf/JWKS',audience:'api://gateway-2',keyIds:['consent-a-signing'],maxLifetimeSeconds:180}],
 downstream:toolTrust(),tokenEndpoint:nodes.b.issuer+'/as/token.oauth2',clientId:copilotProfile.toolClientId,clientKeyId:'copilot-sso-exchange',clientAlgorithm:'RS256',clientAssertionAudience:nodes.b.issuer,
 targetParameter:'resource',requestedResource:'urn:copilot:delegated:tool',scope:profile.scope,timeoutMs:5000,
};}
