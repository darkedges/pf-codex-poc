import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { admin, load, read, save, nodes, local, root } from './common.mjs';

const node = process.argv[2];
if (!Object.hasOwn(nodes, node)) throw Error('Specify a or b');
const alreadyProvisioned = existsSync(resolve(local, `admin-${node}.json`));
let ready = false;
for (let attempt = 0; attempt < 40; attempt++) {
  try { await admin(node, alreadyProvisioned ? 'version' : 'keyPairs/sslServer/settings', 'GET', undefined, !alreadyProvisioned); ready = true; break; }
  catch (error) { if (error.status === 401 || error.status === 403) throw error; }
  await new Promise(r => setTimeout(r, 3000));
}
if (!ready) throw Error(`PF ${node} not ready; rerun after container startup completes`);
// On first provisioning only, the pinned loopback instance has the image's untrusted TLS key.
let trusted = false;
try { await admin(node, 'version'); trusted = true; } catch {}
if (!trusted) {
  const imported = await admin(node, 'keyPairs/sslServer/import', 'POST', {
    id: 'copilot-localhost', fileData: readFileSync(resolve(local, 'localhost.p12')).toString('base64'), format: 'PKCS12', password: read('tls-password'),
  }, true);
  const id = imported.id;
  await admin(node, 'keyPairs/sslServer/settings', 'PUT', {
    adminConsoleCertRef: { id }, runtimeServerCertRef: { id }, activeAdminConsoleCerts: [{ id }], activeRuntimeServerCerts: [{ id }],
  }, true);
  const restart = spawnSync('docker', ['compose', '--env-file', '.local/pingfederate/compose.env', '-f', 'infra/pingfederate/compose.yaml', 'restart', `pf-${node}`], { cwd: root, stdio: 'inherit' });
  if (restart.status !== 0) throw Error('Dedicated PF restart failed');
}
ready = false;
for (let attempt = 0; attempt < 40; attempt++) {
  try { await admin(node, 'version'); ready = true; break; } catch {}
  await new Promise(r => setTimeout(r, 3000));
}
if (!ready) throw Error(`PF ${node} trusted TLS did not become ready`);
const credentials = alreadyProvisioned ? load(`admin-${node}.json`) : load(`bootstrap-admin-${node}.json`);
const intendedPassword = read(`admin-${node}-password`);
if (credentials.password !== intendedPassword) {
  await admin(node, 'administrativeAccounts/changePassword', 'POST', { currentPassword: credentials.password, newPassword: intendedPassword });
  credentials.password = intendedPassword;
}
if (!alreadyProvisioned || credentials.password === intendedPassword) {
  save(`admin-${node}.json`, credentials);
}
console.log(`PF ${node}: trusted local TLS and dedicated administrator credential ready`);
