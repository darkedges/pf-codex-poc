import test from 'node:test';import assert from 'node:assert/strict';import {documentChatCallbackFingerprint} from '../../scripts/pf/document-chat-callback.mjs';
test('provider callback fingerprint ignores only randomized encrypted-secret bytes; configuration stays pinned',()=>{
 const client={clientId:'copilot-studio-generic-oauth',enabled:true,clientAuth:{type:'SECRET',encryptedSecret:'first-random-ciphertext'},redirectUris:['https://portal.test/provider-callback'],restrictedScopes:['copilot.login'],modificationDate:'original'};
 const other=structuredClone(client);other.clientAuth.encryptedSecret='second-random-ciphertext';assert.equal(documentChatCallbackFingerprint(client),documentChatCallbackFingerprint(other));
 for(const change of [{enabled:false},{redirectUris:['https://other.test/callback']},{restrictedScopes:['extra']},{modificationDate:'changed'},{clientAuth:{type:'NONE'}}])assert.notEqual(documentChatCallbackFingerprint(client),documentChatCallbackFingerprint({...client,...change}));
 const jwt={clientId:'copilot-consent-portal',clientAuth:{type:'PRIVATE_KEY_JWT',enforceReplayPrevention:true}};assert.notEqual(documentChatCallbackFingerprint(jwt),documentChatCallbackFingerprint({...jwt,clientAuth:{...jwt.clientAuth,enforceReplayPrevention:false}}));assert.equal(client.clientAuth.encryptedSecret,'first-random-ciphertext');
});
