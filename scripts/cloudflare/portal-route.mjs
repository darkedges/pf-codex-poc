export const portalPathPattern='^/(?:login|callback|approve|provider-login|provider-callback|check|revoke|logout)?$';
export function portalTunnelCandidate(source,publicCertificate){
 if(typeof source!=='string'||source.includes('agent.copilot.darkedges.com')||typeof publicCertificate!=='string'||!publicCertificate.endsWith('portal-origin-cert.pem')||/[\r\n]/.test(publicCertificate))throw Error('Portal ingress source or TLS pin invalid');
 const marker='  - service: http_status:404',position=source.lastIndexOf(marker);if(position<0||source.slice(position).trimEnd()!==marker)throw Error('Final tunnel deny-all required');
 const newline=source.includes('\r\n')?'\r\n':'\n';
 const entry=['  - hostname: agent.copilot.darkedges.com','    path: '+JSON.stringify(portalPathPattern),'    service: https://127.0.0.1:9466','    originRequest:','      httpHostHeader: agent.copilot.darkedges.com','      originServerName: localhost','      caPool: '+JSON.stringify(publicCertificate),'      noTLSVerify: false','  - hostname: agent.copilot.darkedges.com','    service: http_status:404',''].join(newline);
 return source.slice(0,position)+entry+source.slice(position);
}
