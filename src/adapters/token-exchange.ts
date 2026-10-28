export type DelegatedClaims = {
  iss: string; aud: string; sub: string; act: { sub: string; iss: string };
  org_id: string; delegation_id: string; execution_mode: 'interactive' | 'autonomous';
  scope: string; iat: number; nbf: number; exp: number; jti: string;
};
export interface TokenVerifier { verify(token: string): Promise<DelegatedClaims> }
export interface TokenExchanger { exchange(token: string): Promise<{ accessToken: string; claims: DelegatedClaims }> }
export type ExchangeErrorCode = 'configuration' | 'invalid_token' | 'policy_denied' | 'exchange_failed';
export class ExchangeError extends Error {
  code: ExchangeErrorCode;
  constructor(code: ExchangeErrorCode) { super(code); this.name = 'ExchangeError'; this.code = code; }
}
