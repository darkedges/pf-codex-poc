// Call only after signature/issuer/audience verification. This waits for actual
// validity; it never changes the clock, expiration, or verifier's tolerance.
export async function waitForVerifiedValidFrom(claims:{iat:number;nbf:number},signal:AbortSignal){
 if(signal.aborted||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.nbf))throw Error('Verified credential unavailable');
 const delay=Math.max(claims.iat,claims.nbf)*1000-Date.now();if(delay>5000)throw Error('Verified credential unavailable');if(delay<=0)return;
 await new Promise<void>((done,reject)=>{const abort=()=>{clearTimeout(timer);signal.removeEventListener('abort',abort);reject(Error('Verified credential unavailable'));},timer=setTimeout(()=>{signal.removeEventListener('abort',abort);done();},delay+5);signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();});
 if(signal.aborted||Date.now()<Math.max(claims.iat,claims.nbf)*1000)throw Error('Verified credential unavailable');
}
