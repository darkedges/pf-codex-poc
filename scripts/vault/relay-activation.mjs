import {isDeepStrictEqual} from 'node:util';
export function validateServiceCallerTrust(pins,monitorPin,activation,evidence){
 const pin=v=>typeof v==='string'&&/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(v);
 if(!pin(monitorPin))throw Error('Invalid service caller trust');
 if(activation===undefined){if(!isDeepStrictEqual(pins,[monitorPin]))throw Error('Unselected service caller');return;}
 if(!activation||Object.keys(activation).sort().join()!=='configurationSha256,relayCertificateSha256,relayVaultVersion,version'||activation.version!==1||!Number.isSafeInteger(activation.relayVaultVersion)||activation.relayVaultVersion<1||!pin(activation.relayCertificateSha256)||activation.relayCertificateSha256===monitorPin||!/^[a-f0-9]{64}$/.test(activation.configurationSha256)||!evidence||evidence.version!==activation.relayVaultVersion||evidence.pin!==activation.relayCertificateSha256||evidence.configurationSha256!==activation.configurationSha256||!isDeepStrictEqual(pins,[monitorPin,activation.relayCertificateSha256]))throw Error('Relay caller activation does not match selected custody');
}
