import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
const base = join(process.cwd(), '.local', 'keys');
mkdirSync(base, { recursive: true, mode: 0o700 });
for (const name of ['pf-a','pf-b','delegation','entra']) {
  const priv = join(base, `${name}.private.pem`);
  const pub = join(base, `${name}.public.pem`);
  if (existsSync(priv) || existsSync(pub)) {
    if (!existsSync(priv) || !existsSync(pub)) throw Error(`Only one half of ${name} keypair exists`);
    continue;
  }
  const {privateKey,publicKey} = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {type:'spki',format:'pem'},
    privateKeyEncoding: {type:'pkcs8',format:'pem'}
  });
  writeFileSync(priv, privateKey, {mode: 0o600});
  writeFileSync(pub, publicKey, {mode: 0o644});
}
console.log('Local-only mock signing keys present. Never commit or use in production.');
