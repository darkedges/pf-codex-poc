import {signingDomain} from './device-contract.ts';
import type {DeviceProof} from './device-contract.ts';
function decode(value:string,max:number){if(typeof value!=='string'||!value||value.length>max||!/^[A-Za-z0-9_-]+$/.test(value))throw Error();return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
// Android Signature emits ASN.1 DER; WebCrypto ECDSA verifies IEEE P1363.
// Accept only a canonical two-integer P-256 sequence, not arbitrary ASN.1.
export function derToP1363(der:Uint8Array){
 if(der.length<8||der.length>72||der[0]!==0x30||der[1]!==der.length-2)throw Error('invalid_device_proof');
 let offset=2;const out=new Uint8Array(64);
 for(let index=0;index<2;index++){
  if(der[offset++]!==2)throw Error('invalid_device_proof');const length=der[offset++];if(length<1||length>33||offset+length>der.length)throw Error('invalid_device_proof');
  let integer=der.subarray(offset,offset+length);offset+=length;if(integer[0]&128)throw Error('invalid_device_proof');
  if(integer.length>1&&integer[0]===0){if(!(integer[1]&128))throw Error('invalid_device_proof');integer=integer.subarray(1);}
  if(integer.length>32)throw Error('invalid_device_proof');out.set(integer,index*32+32-integer.length);
 }
 if(offset!==der.length)throw Error('invalid_device_proof');return out;
}
export async function verifyDeviceProof(proof:DeviceProof){
 try{
  if(proof.algorithm!=='SHA256withECDSA-DER'||!/^fc-mobile-spike-v1:[A-Za-z0-9_-]{43}$/.test(proof.challenge))return false;
  const key=await crypto.subtle.importKey('spki',decode(proof.publicKeySpki,1024),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,derToP1363(decode(proof.signature,128)),new TextEncoder().encode(signingDomain+proof.challenge));
 }catch{return false;}
}
