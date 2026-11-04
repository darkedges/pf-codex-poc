import {ProviderRelayError} from './provider-tool-relay.ts';
// Configured trust only: never derive aliases from a token or a caller header.
export function relayLoginIssuers(primary:string,additional:string[]=[]):readonly string[]{
 try{
  if(!Array.isArray(additional)||additional.length>4)throw Error();
  const issuers=[primary,...additional];if(new Set(issuers).size!==issuers.length)throw Error();
  for(const issuer of issuers){if(typeof issuer!=='string'||issuer.length>2048||/\s/.test(issuer))throw Error();const u=new URL(issuer);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error();}
  return Object.freeze(issuers);
 }catch{throw new ProviderRelayError('configuration');}
}
