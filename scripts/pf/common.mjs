import { request } from 'node:https';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
export const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
export const local = resolve(root, '.local/pingfederate');
export const nodes = { a: { admin: 'https://localhost:9996', issuer: 'https://localhost:9033' }, b: { admin: 'https://localhost:9997', issuer: 'https://localhost:9034' } };
export const read = name => readFileSync(resolve(local, name), 'utf8');
export const save = (name, value) => { mkdirSync(local, { recursive: true }); writeFileSync(resolve(local, name), typeof value === 'string' ? value : JSON.stringify(value, null, 2), { mode: 0o600 }); };
export const load = name => JSON.parse(read(name));
export function call(url, { method = 'GET', body, admin, bootstrapTls = false, form = false } = {}) {
  const target = new URL(url);
  if (target.protocol !== 'https:' || target.hostname !== 'localhost' || !['9996','9997','9033','9034'].includes(target.port)) throw Error('Refused non-lab endpoint');
  if (bootstrapTls && (!['9996','9997'].includes(target.port) || !target.pathname.startsWith('/pf-admin-api/v1/keyPairs/sslServer'))) throw Error('TLS bootstrap restricted to new local certificate endpoints');
  const data = body === undefined ? undefined : form ? new URLSearchParams(body).toString() : JSON.stringify(body);
  return new Promise((resolveResult, reject) => {
    const headers = { Accept: 'application/json', 'X-XSRF-Header': 'PingFederate' };
    if (data) { headers['Content-Type'] = form ? 'application/x-www-form-urlencoded' : 'application/json'; headers['Content-Length'] = Buffer.byteLength(data); }
    if (admin) headers.Authorization = 'Basic ' + Buffer.from(`${admin.username}:${admin.password}`).toString('base64');
    const req = request(target, { method, ca: read('ca.pem'), rejectUnauthorized: !bootstrapTls, headers, timeout: 15000 }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 2_000_000) req.destroy(Error('Response too large')); });
      res.on('end', () => {
        let value;
        try { value = JSON.parse(data); } catch { value = undefined; }
        resolveResult({ status: res.statusCode, value });
      });
      res.on('error', () => reject(Error('Local HTTPS response failed')));
    });
    req.on('timeout', () => req.destroy(Error('Local HTTPS timeout')));
    // A socket inactivity timeout alone need not cover TLS connection establishment.
    const deadline = setTimeout(() => req.destroy(Error('Local HTTPS deadline exceeded')), 15000);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', () => reject(Error('Local HTTPS request failed')));
    req.end(data);
  });
}
export async function admin(node, path, method = 'GET', body, bootstrapTls = false) {
  const credentials = existsSync(resolve(local, `admin-${node}.json`)) ? load(`admin-${node}.json`) : load(`bootstrap-admin-${node}.json`);
  const r = await call(nodes[node].admin + '/pf-admin-api/v1/' + path, { method, body, admin: credentials, bootstrapTls });
  if (r.status < 200 || r.status >= 300) {
    // Save private diagnostics locally only; API responses can contain credentials.
    save('last-admin-error.json', { node, path, method, status: r.status, response: r.value });
    const error = Error(`PF ${node} administration ${method} ${path}: HTTP ${r.status}; private diagnostics saved locally`);
    error.status = r.status;
    throw error;
  }
  return r.value;
}
