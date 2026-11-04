export const mobilePathPattern='^/(?:\\.well-known/assetlinks\\.json|mobile/(?:callback|return)|v1/mobile/(?:config|login/start|enrollment/(?:claim|complete)|session/(?:challenge|complete)|access/(?:terms|approve|status|revoke)|chat/(?:messages|result|cancel)))?$';
// Exact local candidate only; no write/restart/DNS operation.
export function mobileTunnelCandidate(source,certificate){
 if(typeof source!=='string'||typeof certificate!=='string'||!certificate.endsWith('/mobile-origin-cert.pem')||/[\r\n]/.test(certificate))throw Error('mobile_ingress_configuration');
 const newline=source.includes('\r\n')?'\r\n':'\n',lines=source.split(/\r?\n/),agent=[];let hostname='',par=0;
 for(let i=0;i<lines.length;i++){const h=/^  - hostname: (.+)$/.exec(lines[i]);if(h)hostname=h[1];if(hostname==='pf-a.copilot.darkedges.com'&&/^    path: /.test(lines[i])){const path=JSON.parse(lines[i].slice(10));if(!path.includes('/as/(?:authorization|token)\\.oauth2'))throw Error('mobile_pf_ingress_drift');lines[i]='    path: '+JSON.stringify(path.replace('/as/(?:authorization|token)\\.oauth2','/as/(?:authorization|token|par)\\.oauth2'));par++;}if(h?.[1]==='agent.copilot.darkedges.com')agent.push(i);}
 if(par!==1||agent.length!==2||lines[agent[1]+1]!=='    service: http_status:404'||!source.trimEnd().endsWith('  - service: http_status:404'))throw Error('mobile_ingress_drift');
 const entry=['  - hostname: agent.copilot.darkedges.com','    path: '+JSON.stringify(mobilePathPattern),'    service: https://127.0.0.1:9468','    originRequest:','      httpHostHeader: agent.copilot.darkedges.com','      originServerName: localhost','      caPool: '+JSON.stringify(certificate),'      noTLSVerify: false'];
 lines.splice(agent[0],agent[1]-agent[0],...entry);return lines.join(newline);
}
