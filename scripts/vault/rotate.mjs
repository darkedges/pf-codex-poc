import { operator,keyName,privateSave } from './common.mjs';
import { publicProfile,activateProfile } from './profile.mjs';
import { publishAuthorityTrust } from './trust.mjs';
import { load } from '../pf/common.mjs';
export async function rotateAuthority(){
 await operator(`/transit/keys/${keyName}/rotate`,{method:'POST',body:{}});
 const profile=await publicProfile();
 // Publish overlap before selecting the new signing version for new service processes.
 await publishAuthorityTrust(profile.trust);activateProfile(profile);
 privateSave('rotation.json',{version:profile.config.version,stagedAt:new Date().toISOString()});return profile;
}
export async function retirePrevious(){
 const profile=await publicProfile(),selected=load('authority-transit-config.json');
 if(profile.config.version!==selected.version)throw Error('Activate latest signing version before retirement');
 // This is explicit key retirement, including emergency rejection of outstanding proofs.
 // Routine rotation must first drain old authorities and wait assertion lifetime + skew.
 await operator(`/transit/keys/${keyName}/config`,{method:'POST',body:{min_encryption_version:profile.config.version}});
 const retired=await publicProfile();await publishAuthorityTrust(retired.trust);activateProfile(retired);return retired;
}
if(process.argv[1]?.replaceAll('\\','/').endsWith('/scripts/vault/rotate.mjs')){
 if(process.argv[2]==='rotate'){const p=await rotateAuthority();console.log(`Authority version ${p.config.version} staged with PF overlap. Restart authority processes before retiring old keys.`);}
 else if(process.argv[2]==='retire'){await retirePrevious();console.log('Earlier signing versions disabled and removed from PF A trust.');}
 else throw Error('Specify rotate or retire explicitly');
}
