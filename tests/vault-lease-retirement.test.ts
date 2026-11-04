import { test } from 'node:test';
import assert from 'node:assert/strict';
import { retireRuntimeLease } from '../scripts/vault/retire-lease.mjs';

test('Vault 200 retirement requires independent confirmation that accessor is absent', async () => {
  const paths: string[] = [];
  await retireRuntimeLease(async (path: string) => {
    paths.push(path);
    return path.endsWith('revoke-accessor') ? { status: 200 } : { status: 400, value: { errors: ['invalid accessor'] } };
  }, 'private-token', 'private-accessor');
  assert.equal(paths.length, 2);
});
test('Vault retirement fails closed on active or ambiguous accessor lookup', async () => {
  for (const lookup of [{status:200,value:{data:{}}},{status:403},{status:500},{status:400,value:{errors:['unknown error']}}]) {
    await assert.rejects(retireRuntimeLease(async (path: string) => path.endsWith('revoke-accessor') ? {status:200} : lookup, 'private-token', 'private-accessor'), /retired/);
  }
});
test('Vault 204 and known absent-accessor responses remain supported', async () => {
  for (const response of [{status:204},{status:400,value:{errors:['invalid accessor']}}]) {
    await retireRuntimeLease(async () => response, 'private-token', 'private-accessor');
  }
});
test('Vault retirement rejects unexpected response without leaking credentials', async () => {
  await assert.rejects(retireRuntimeLease(async () => ({status:403}), 'private-token', 'private-accessor'), /^Error: Previous runtime lease could not be retired$/);
});
