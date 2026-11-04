import test from 'node:test';import assert from 'node:assert/strict';import {projectRelayHttpDiagnostic} from '../scripts/vault/relay-http-diagnostics.mjs';
test('IPC HTTP projection discards all credential and request data',()=>{
 const result=projectRelayHttpDiagnostic({event:'provider_relay_http',status:401,credentials:{provider:'present',caller:'missing',token:'synthetic-private'},headers:{authorization:'synthetic-private'},body:'synthetic-private',reason:'synthetic-private'});
 assert.deepEqual(result,{event:'provider_relay_http',status:401,credentials:{provider:'present',caller:'missing'}});
 assert.ok(!JSON.stringify(result).includes('synthetic-private'));
});
test('IPC HTTP projection refuses unbounded or unrecognized metadata',()=>{
 for(const value of [null,{}, {event:'provider_relay_http',status:401,credentials:{provider:'synthetic-private',caller:'present'}},{event:'provider_relay_http',status:'401',credentials:{provider:'present',caller:'present'}},{event:'provider_relay_http',status:999,credentials:{provider:'present',caller:'present'}}])assert.equal(projectRelayHttpDiagnostic(value),undefined);
});
