import test from 'node:test';
import assert from 'node:assert/strict';
import { authoritySettings } from '../../scripts/pf/authority-config.mjs';
test('unknown authority backend fails closed instead of selecting development',()=>{assert.throws(()=>authoritySettings({AUTHORITY_SIGNER:'unknown'}));});
test('explicit development remains isolated from the Vault profile',()=>{const config=authoritySettings({AUTHORITY_SIGNER:'development'});assert.equal(config.AUTHORITY_SIGNER,'development');assert.equal(config.AUTHORITY_VAULT_TOKEN_FILE,undefined);});
test('missing remote configuration cannot silently use a development key',()=>{assert.throws(()=>authoritySettings({AUTHORITY_SIGNER:'vault-transit',AUTHORITY_TRANSIT_CONFIG_FILE:'missing-authority-config.json'}));});
