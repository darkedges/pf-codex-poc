import type { DelegatedClaims,TokenVerifier } from './token-exchange.ts';
import type {ProviderAccessClaims} from '../identity/provider-access.ts';
export type CopilotErrorCode='configuration'|'invalid_request'|'invalid_token'|'policy_denied'|'session_denied'|'session_busy'|'expired'|'sso_expired'|'oauth_invalid'|'challenge_replay'|'protocol_error'|'unavailable'|'capacity';
export class CopilotError extends Error {
 readonly code:CopilotErrorCode;
 constructor(code:CopilotErrorCode){super(code);this.name='CopilotError';this.code=code;}
}
export type TokenPostRule={origin:string;requiredQueryParameters:string[]}&({pathPrefix:string;pathExact?:never}|{pathExact:string;pathPrefix?:never});
export type ProviderSso={issuer:string;audience:string;scope:string;maxLifetimeSeconds:number};
export type DirectLineConfig={endpoint:string;brokerAudience:string;ssoAudience:string;scope:string;providerSso?:ProviderSso;botId:string;trustedOrigins:string[];tokenPostRules:TokenPostRule[];timeoutMs:number;maxSessions:number;sessionLifetimeSeconds:number;maxActivities:number};
export type CopilotState='awaiting_oauth'|'token_posted'|'closed';
export type Conversation={handle:string;state:CopilotState;expiresAt:number};
export type CopilotPage={state:CopilotState;messages:{id:string;text:string}[]};
export interface CopilotAdapter {
 open(brokerToken:string):Promise<Conversation>;
 send(handle:string,brokerToken:string,text:string):Promise<{submitted:true}>;
 poll(handle:string,brokerToken:string):Promise<CopilotPage>;
 refresh(handle:string,brokerToken:string):Promise<Conversation>;
 close(handle:string,brokerToken:string):Promise<{closed:true}>;
}
export type DirectLineDependencies={
 verifier:TokenVerifier;ssoVerifier?:TokenVerifier;
 providerVerifier?:{verify:(raw:string)=>Promise<ProviderAccessClaims>};
 // Must use a trusted issuer-qualified identity registry and the verified broker context.
 bindProviderIdentity?:(provider:Readonly<ProviderAccessClaims>,broker:Readonly<DelegatedClaims>,evidence:{brokerToken:string;signal:AbortSignal})=>Promise<void>;
 // Trusted internal relay lifecycle; credentials never come from message fields.
 providerSession?:{bind:(brokerToken:string,providerToken:string,signal:AbortSignal)=>Promise<void>;invalidate:(providerToken:string)=>void};
 secret:(signal:AbortSignal)=>Promise<string>;
 issueSsoToken:(request:{claims:Readonly<DelegatedClaims>;brokerToken:string;audience:string;scope:string;signal:AbortSignal})=>Promise<string>;
 authorise:(claims:Readonly<DelegatedClaims>,evidence:{accessToken:string})=>Promise<void>;
 fetch?:typeof fetch;now?:()=>number;
 observe?:(event:{event:'copilot_directline';operation:'open'|'send'|'poll'|'refresh'|'close';outcome:'ok'|CopilotErrorCode;durationMs:number})=>void;
};
