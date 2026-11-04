export type KeyMetadata={publicKeySpki:string;securityLevel:string};
export type DeviceProof={challenge:string;publicKeySpki:string;signature:string;algorithm:string};
export type NativeDevice={
 getStatus():Promise<{available:boolean;hasKey:boolean;securityLevel:string}>;
 createKey():Promise<KeyMetadata>;
 signChallenge(options:{challenge:string}):Promise<DeviceProof>;
 lock():Promise<void>;
};
export const challengePrefix='fc-mobile-spike-v1:';
export const signingDomain='federated-copilot/device-test/v1\n';
export function createChallenge(){const bytes=crypto.getRandomValues(new Uint8Array(32));return challengePrefix+encode(bytes);}
export function encode(bytes:Uint8Array){return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
