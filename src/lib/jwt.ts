// Educational, pinned-key RS256 JWT subset for LOCAL DEMO ONLY.
// Replace with a maintained JOSE library, JWKS rotation/caching and hardened validation before production.
import { createSign, createVerify, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export class AuthError extends Error { constructor(message='unauthorized') { super(message); this.name='AuthError'; } }
export type JsonClaims = Record<string, unknown>;
export const now = () => Math.floor(Date.now() / 1000);
const b64 = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const decode = (value: string) => JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
export function localKey(name: 'pf-a'|'pf-b'|'delegation'|'entra', part: 'private'|'public'): string {
  return readFileSync(resolve('.local/keys', `${name}.${part}.pem`), 'utf8');
}
export function signJwt(claims: JsonClaims, privatePem: string, kid: string, ttlSeconds = 120): string {
  const timestamp = now();
  const payload = { ...claims, iat: timestamp, nbf: timestamp, exp: timestamp+ttlSeconds, jti: randomUUID() };
  const input = `${b64({alg:'RS256',typ:'JWT',kid})}.${b64(payload)}`;
  const signer = createSign('RSA-SHA256');
  signer.update(input);
  signer.end();
  return `${input}.${signer.sign(privatePem).toString('base64url')}`;
}
export function verifyJwt(token: string, publicPem: string, expected: {issuer:string; audience:string; requireActor?:boolean}): JsonClaims {
  if (typeof token !== 'string' || token.length > 16000) throw new AuthError();
  const parts = token.split('.');
  if (parts.length !== 3) throw new AuthError();
  let header: Record<string,unknown>, claims: JsonClaims;
  try { header = decode(parts[0]); claims = decode(parts[1]); } catch { throw new AuthError(); }
  if (header.alg !== 'RS256' || header.typ !== 'JWT') throw new AuthError('Invalid token algorithm/type');
  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${parts[0]}.${parts[1]}`);
  verifier.end();
  const validSignature = verifier.verify(publicPem, Buffer.from(parts[2], 'base64url'));
  if (!validSignature) throw new AuthError('Invalid token signature');
  if (claims.iss !== expected.issuer || claims.aud !== expected.audience) throw new AuthError('Invalid issuer or audience');
  if (typeof claims.sub !== 'string' || !claims.sub) throw new AuthError('Missing subject');
  if (typeof claims.exp !== 'number' || claims.exp <= now() || typeof claims.nbf !== 'number' || claims.nbf > now()+15 || typeof claims.iat !== 'number' || claims.iat > now()+15) throw new AuthError('Invalid token times');
  if (expected.requireActor && (!claims.act || typeof claims.act !== 'object' || typeof (claims.act as Record<string,unknown>).sub !== 'string')) throw new AuthError('Missing agent actor');
  return claims;
}
