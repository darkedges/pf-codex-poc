import test from 'node:test';import assert from 'node:assert/strict';
import {validateServiceCallerTrust} from '../scripts/vault/relay-activation.mjs';
const monitor=Array(32).fill('AA').join(':'),relay=Array(32).fill('BB').join(':'),hash='a'.repeat(64);
const activation={version:1,relayVaultVersion:1,relayCertificateSha256:relay,configurationSha256:hash};
const evidence={version:1,pin:relay,configurationSha256:hash};
test('original monitor-only service works without relay activation',()=>{assert.doesNotThrow(()=>validateServiceCallerTrust([monitor],monitor));assert.throws(()=>validateServiceCallerTrust([monitor,relay],monitor));});
test('only the enrolled, version-pinned relay can overlap the existing caller',()=>assert.doesNotThrow(()=>validateServiceCallerTrust([monitor,relay],monitor,activation,evidence)));
for(const [pins,a,e] of [[[relay],activation,evidence],[[monitor,relay],{...activation,extra:true},evidence],[[monitor,relay],activation,{...evidence,version:2}],[[monitor,relay],activation,{...evidence,pin:monitor}],[[monitor,relay],activation,{...evidence,configurationSha256:'b'.repeat(64)}],[[monitor,relay,relay],activation,evidence]])test('unselected, changed or duplicate caller trust fails closed',()=>assert.throws(()=>validateServiceCallerTrust(pins,monitor,a,e)));
