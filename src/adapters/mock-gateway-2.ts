import { verifyJwt, localKey, AuthError } from '../lib/jwt.ts';
import { authorise, type Mode } from '../lib/policy.ts';
import { tokenExchange, envUrl } from '../lib/http.ts';
import type { DelegatedClaims, TokenExchanger } from './token-exchange.ts';

export class MockGateway2Exchange implements TokenExchanger {
  async exchange(original: string) {
    if (process.env.DEMO_ONLY !== 'true' || process.env.NODE_ENV === 'production') throw new AuthError('Mock disabled');
    const claims = verifyJwt(original, localKey('pf-a', 'public'), { issuer: 'http://pf-a.demo.local', audience: 'api://gateway-2', requireActor: true });
    const actor = claims.act as Record<string, unknown>;
    if (actor.iss !== 'http://pf-a.demo.local' || claims.scope !== 'copilot.invoke') throw new AuthError('Invalid incoming claims');
    authorise({ grantId: String(claims.delegation_id), user: String(claims.sub), agent: String(actor.sub), mode: String(claims.execution_mode) as Mode, scope: 'copilot.invoke', resource: 'sharepoint:approved-research' });
    const accessToken = await tokenExchange(envUrl('PF_B_URL', 'http://127.0.0.1:9202') + '/as/token.oauth2', {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', client_id: 'gateway-2-token-exchange', subject_token: original,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', audience: 'api://copilot-broker',
    });
    const output = verifyJwt(accessToken, localKey('pf-b', 'public'), { issuer: 'http://pf-b.demo.local', audience: 'api://copilot-broker', requireActor: true });
    return { accessToken, claims: output as DelegatedClaims };
  }
}
