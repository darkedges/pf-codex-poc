import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';
const root=resolve(fileURLToPath(new URL('../../',import.meta.url)));
const tunnelId='a979d27b-f2cd-45cf-aada-b44c850e3a0e';
const escape=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
export function activationCandidate(review){
 if(review?.callbackCapturedLocally!==true||!Array.isArray(review.resources)||!review.resources.length||review.resources.length>50||!Array.isArray(review.cookies)||!review.cookies.some(c=>c.name==='PF'))throw Error('Completed bounded local browser review required');
 for(const cookie of review.cookies)if(cookie.secure!==true||cookie.httpOnly!==true||![null,'pf-a.copilot.darkedges.com'].includes(cookie.domain))throw Error('Cookie review requires secure host-bound cookies');
 for(const r of review.resources)if(typeof r.path!=='string'||!/^\/assets\/[A-Za-z0-9_./-]+$/.test(r.path)||r.path.split('/').includes('..')||r.path.includes('//')||![200,404].includes(r.status)||(r.directlyLinked&&r.status!==200))throw Error('Unapproved reviewed asset path or response');
 const assets=[...new Set(review.resources.filter(r=>r.status===200).map(r=>r.path))].sort();
 const paths={a:'^(?:/as/(?:authorization|token)\\.oauth2|/as/[A-Za-z0-9_-]{1,128}/resume/as/authorization\\.ping|/pf/JWKS|/\\.well-known/openid-configuration|'+assets.map(escape).join('|')+')$',b:'^/(?:pf/JWKS|\\.well-known/openid-configuration)$'};
 const lines=['# REVIEW CANDIDATE ONLY — NOT ACTIVE','tunnel: '+tunnelId,"credentials-file: 'E:/development/projects/copilot/federated-copilot-codex/.local/cloudflare-connector/credentials.json'",'metrics: 127.0.0.1:19473','loglevel: warn','transport-loglevel: warn','no-autoupdate: true','ingress:'];
 for(const [node,port]of [['a',9033],['b',9034]])lines.push('  - hostname: pf-'+node+'.copilot.darkedges.com','    path: '+JSON.stringify(paths[node]),'    service: https://127.0.0.1:'+port,'    originRequest:','      originServerName: localhost','      httpHostHeader: pf-'+node+'.copilot.darkedges.com',"      caPool: 'E:/development/projects/copilot/federated-copilot-codex/.local/pingfederate/ca.pem'",'      noTLSVerify: false');
 lines.push('  - service: http_status:404');
 return{approved:false,certificateVerified:false,publicRoutesEnabled:false,tunnelId,
  dns:[{hostname:'pf-a.copilot.darkedges.com',type:'CNAME',target:tunnelId+'.cfargotunnel.com',proxied:true},{hostname:'pf-b.copilot.darkedges.com',type:'CNAME',target:tunnelId+'.cfargotunnel.com',proxied:true}],
  paths,reviewedAssets:assets,unresolvedCssResources:review.resources.filter(r=>r.status!==200).map(r=>r.path),renderedBrowserVerified:review.renderedBrowserVerified===true,
  blockers:['Active edge certificate coverage not verified','Rendered browser and missing CSS-only resource impact not verified','Exact Cloudflare DNS plan and exposure approval pending'],yaml:lines.join('\n')+'\n'};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==2)throw Error('Offline planning only; no apply arguments supported');
 const review=JSON.parse(readFileSync(resolve(root,'.local/copilot/browser-review.json'),'utf8'));
 const active=readFileSync(resolve(root,'.local/cloudflare-connector/config.yaml'),'utf8');
 const blocks=active.split(/^ingress:/m);
 if(blocks.length!==2||!/^\s*- service: http_status:404\s*$/.test(blocks[1]))throw Error('Active connector must remain deny-all during planning');
 const candidate=activationCandidate(review),directory=resolve(root,'.local/cloudflare-plan');mkdirSync(directory,{recursive:true});
 const hash=value=>createHash('sha256').update(value).digest('hex');
 const plan={...candidate,activeConfigSha256:hash(active),candidateSha256:hash(candidate.yaml)};
 writeFileSync(resolve(directory,'activation.json'),JSON.stringify(plan,null,2));writeFileSync(resolve(directory,'activation-candidate.yaml'),candidate.yaml);
 console.log(JSON.stringify({status:'blocked-not-applied',activeConfigSha256:plan.activeConfigSha256,candidateSha256:plan.candidateSha256,exactAssetPaths:candidate.reviewedAssets.length,blockers:candidate.blockers},null,2));
}
