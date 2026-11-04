import test from 'node:test';
import assert from 'node:assert/strict';
import { confirmEmptyPacList } from '../src/provisioning/pac-output.ts';
test('empty PAC JSON requires an exact independent text confirmation',()=>{
 const message='Connected as maker@example.test\r\n\nListing all environments from your tenant...\n\nListing environment groups from your tenant...\nNo environments were found in your tenant.\n';
 assert.deepEqual(confirmEmptyPacList(message),[]);
 for(const invalid of ['', '[]','No environments were found in your tenant.',message+'Error: unauthorized',message.replace('No environments were found in your tenant.','Environment exists'),message.replace('Connected as maker@example.test','Connected as secret token value')])assert.throws(()=>confirmEmptyPacList(invalid));
});
