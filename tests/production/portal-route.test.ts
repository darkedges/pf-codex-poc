import test from 'node:test';import assert from 'node:assert/strict';import {portalPathPattern,portalTunnelCandidate} from '../../scripts/cloudflare/portal-route.mjs';
test('portal route adds only its fixed host/path/origin and preserves previous tunnel content',()=>{
 const before='tunnel: fixed\n  - hostname: pf-a.test\n    service: https://127.0.0.1:9033\n  - service: http_status:404\n',after=portalTunnelCandidate(before,'E:\\project\\portal-origin-cert.pem');assert.ok(after.startsWith(before.slice(0,before.lastIndexOf('  - service:'))));assert.ok(after.endsWith('  - service: http_status:404\n'));assert.match(after,/httpHostHeader: agent.copilot.darkedges.com/);assert.match(after,/noTLSVerify: false/);
 const paths=new RegExp(portalPathPattern);for(const path of ['/','/login','/callback','/provider-callback','/check','/revoke','/logout'])assert.ok(paths.test(path));for(const path of ['/admin','/v1/health','/check/child','/metrics','//login'])assert.equal(paths.test(path),false);
});
test('portal route refuses duplicate public host, missing deny-all and certificate-path injection',()=>{
 for(const source of ['no deny','agent.copilot.darkedges.com\n  - service: http_status:404','  - service: http_status:404\n  - service: https://evil.test'])assert.throws(()=>portalTunnelCandidate(source,'E:\\portal-origin-cert.pem'));
 assert.throws(()=>portalTunnelCandidate('  - service: http_status:404','E:\\portal-origin-cert.pem\nnoTLSVerify: true'));
});
