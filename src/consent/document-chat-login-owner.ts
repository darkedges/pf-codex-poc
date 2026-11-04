import {bodyHash} from '../policy/protocol.ts';
// Remember only independently verified OIDC results redeemed by this parent.
// A valid proof from another browser window is not this session's authority.
export function createDocumentChatLoginOwner<T>(verifier:{verify(token:string,nonce:string):Promise<T>}){
 const owned=new Set<string>();let closed=false;
 const fingerprint=(token:string,nonce:string)=>{if(typeof token!=='string'||!token||token.length>16000||typeof nonce!=='string'||!nonce||nonce.length>256)throw Error('document_chat_login_denied');return bodyHash(token)+':'+bodyHash(nonce);};
 return{
  remember(token:string,nonce:string){const hash=fingerprint(token,nonce);if(closed||owned.size>=2||owned.has(hash))throw Error('document_chat_login_denied');owned.add(hash);},
  async verify(token:string,nonce:string){if(closed||!owned.has(fingerprint(token,nonce)))throw Error('document_chat_login_denied');return verifier.verify(token,nonce);},
  close(){closed=true;owned.clear();}
 };
}
