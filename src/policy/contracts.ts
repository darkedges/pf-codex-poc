export type Capability = { scope:string;resource:string };
export type Principal = { id:string;kind:'human'|'agent';issuer:string;subject:string;organisation:string;tokenIssuers?:string[] };
export type GrantInput = { id:string;humanId:string;agentId:string;organisation:string;modes:string[];scopes:string[];resources:string[];expiresAt:number;consent:{reference:string;approvedAt:number;expiresAt:number} };
export type PolicyIdentity = { iss:string;aud?:string;sub:string;act:{iss:string;sub:string};org_id:string;delegation_id:string;execution_mode:string;scope:string };
// Produced only by a configured OIDC verifier, never from request-supplied identity fields.
export type VerifiedLogin={issuer:string;subject:string;audience:string;issuedAt:number;authTime:number;expiresAt:number;tokenHash:string;nonceHash:string};
export class PolicyError extends Error {
  code:string;
  constructor(code='forbidden'){super(code);this.name='PolicyError';this.code=code;}
}
