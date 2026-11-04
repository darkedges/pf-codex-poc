import test from 'node:test';import assert from 'node:assert/strict';
import {sasTiming} from '../scripts/copilot/sas-timing.mjs';
const now=Date.UTC(2026,9,30,0,0,0),expires=now+60000;
for(const value of [String(expires/1000),String(expires),new Date(expires).toISOString(),String(BigInt(expires)*10000n+621355968000000000n)])test('SAS timing emits only relative expiry, not query values',()=>{const result=sasTiming(value,now,new Date(now).toUTCString());assert.equal(result.hostRemainingSeconds,60);assert.equal(result.providerRemainingSeconds,60);assert.ok(!JSON.stringify(result).includes(value));});
for(const value of ['PRIVATE_SAS',undefined,'123','99999999999999999999999999999999999999999999999999999999'])test('unknown expiry formats are diagnostic-only and never echoed',()=>{assert.deepEqual(sasTiming(value,now,null),{format:'unrecognized'});});
