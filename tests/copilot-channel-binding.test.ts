import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {assertChannelBinding,assertBoundCredential} from '../src/copilot/channel-binding.ts';
const settings={tenantId:'11111111-2222-4333-8444-555555555555',environmentId:'22222222-2222-4333-8444-555555555555',copilotId:'33333333-2222-4333-8444-555555555555',schemaName:'test_agent'};
const secret='SYNTHETIC_CHANNEL_SECRET';
const receipt={version:1,...settings,credentialSha256:createHash('sha256').update(secret).digest('hex')};
test('explicit operator binding permits only its exact target and credential',()=>{assertChannelBinding(settings,receipt);assertBoundCredential(receipt,secret);});
for(const key of ['tenantId','environmentId','copilotId','schemaName'])test('changed channel target cannot reuse the credential binding: '+key,()=>{assert.throws(()=>assertChannelBinding({...settings,[key]:key==='schemaName'?'another_agent':'aaaaaaaa-2222-4333-8444-555555555555'},receipt));});
for(const receiptValue of [undefined,{}, {...receipt,version:2},{...receipt,credentialSha256:'PRIVATE_BAD_DIGEST'},{...receipt,schemaName:'older_agent'}])test('missing or malformed binding fails with a sanitized error',()=>{
 assert.throws(()=>assertChannelBinding(settings,receiptValue),e=>String(e).includes('credential_binding_required')&&!String(e).includes('PRIVATE'));
});
test('replaced credential requires a fresh binding and never appears in errors',()=>{assert.throws(()=>assertBoundCredential(receipt,'PRIVATE_REPLACEMENT'),e=>String(e).includes('credential_binding_required')&&!String(e).includes('PRIVATE'));});
