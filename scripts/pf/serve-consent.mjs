import { startPolicy } from './run-policy.mjs';
import { startConsent } from './run-consent.mjs';
const policy=await startPolicy();let consent;
try{
 consent=await startConsent({...process.env,POLICY_API_ORIGIN:policy.origin,CONSENT_PORT:'9460'});
 console.log(`Open ${consent.origin} to sign in and review agent access. Test account passwords are in ignored .local/pingfederate; no credentials are printed.`);
 await new Promise(done=>{process.once('SIGINT',done);process.once('SIGTERM',done);});
}finally{if(consent)await consent.stop();await policy.stop();}
