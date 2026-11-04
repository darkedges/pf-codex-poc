import {setTimeout as pause} from 'node:timers/promises';
import type {DelegatedClaims} from '../adapters/token-exchange.ts';
// Call only after signature/issuer/audience verification. JOSE's bounded skew
// accepts small clock differences for verification; a protected operation still
// waits for actual iat/nbf before releasing/using the verified token.
export async function waitForVerifiedTokenActivation(claims:Readonly<DelegatedClaims>,signal:AbortSignal){
 signal.throwIfAborted();if(![claims.iat,claims.nbf,claims.exp].every(Number.isSafeInteger))throw Error('document_activation_denied');
 const target=Math.max(claims.iat,claims.nbf)*1000;
 if(target-Date.now()>5000||claims.exp*1000<=target||claims.exp*1000<=Date.now())throw Error('document_activation_denied');
 while(Date.now()<target){signal.throwIfAborted();const remaining=target-Date.now();if(remaining>5000)throw Error('document_activation_denied');await pause(remaining,undefined,{signal});}
 signal.throwIfAborted();if(claims.exp*1000<=Date.now())throw Error('document_activation_denied');
}
