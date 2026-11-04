import {PolicyError} from '../policy/contracts.ts';
import {portalRunFiles} from './portal-run.ts';
import {portalSessionPolicy,portalSuccessfulPredecessor} from './portal-session-policy.ts';
const scope='portal-browser-first-live-v1',hostname='agent.copilot.darkedges.com',tunnel='a979d27b-f2cd-45cf-aada-b44c850e3a0e';
const hash=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export function assertPortalActivation(manifest:any,approval:any,current:{manifestSha256:string;files:Record<string,string>},now=Date.now()){
 try{
  if(manifest?.schemaVersion!==1||manifest.scope!==scope||manifest.hostname!==hostname||manifest.tunnelId!==tunnel||manifest.dns?.type!=='CNAME'||manifest.dns.name!==hostname||manifest.dns.content!==tunnel+'.cfargotunnel.com'||manifest.dns.proxied!==true||JSON.stringify(manifest.limits)!==JSON.stringify({grants:1,conversations:1,tokenPosts:1,successfulTools:1,windowSeconds:3600})||![manifest.reviewSha256,manifest.sourceTunnelSha256,manifest.candidateTunnelSha256,manifest.toolClientHash,current.manifestSha256].every(hash))throw Error();
  if(approval?.schemaVersion!==1||approval.approved!==true||approval.scope!==scope||approval.reviewSha256!==manifest.reviewSha256||approval.manifestSha256!==current.manifestSha256||!Number.isSafeInteger(approval.approvedAt)||approval.approvedAt>now+5000||now-approval.approvedAt>86400000)throw Error();
  portalRunFiles(manifest);
  const reviewPath=manifest.runReviewPath??'docs/portal-relay-retry-review.md';if(!['docs/portal-relay-retry-review.md','docs/portal-repeatable-session-review.md'].includes(reviewPath)||approval.runReviewPath!==manifest.runReviewPath)throw Error();
  if(manifest.sessionPolicy!==undefined){const policy=portalSessionPolicy(manifest.sessionPolicy),approved=portalSessionPolicy(approval.sessionPolicy),previous=portalSuccessfulPredecessor(manifest.successfulPredecessor),approvedPrevious=portalSuccessfulPredecessor(approval.successfulPredecessor);if(!manifest.runId||manifest.runId===previous.runId||reviewPath!=='docs/portal-repeatable-session-review.md'||policy.maxSessions!==approved.maxSessions||policy.maxConcurrent!==approved.maxConcurrent||JSON.stringify(previous)!==JSON.stringify(approvedPrevious))throw Error();}else if(approval.sessionPolicy!==undefined)throw Error();
  if(manifest.runId!==approval.runId||manifest.runReviewSha256!==approval.runReviewSha256||manifest.runId!==undefined&&(['predecessorSha256','predecessorJournalSha256','predecessorWindowSha256'].some(k=>!hash(manifest[k])||manifest[k]!==approval[k])||manifest.runReviewSha256!==manifest.files?.[reviewPath]))throw Error();
  if(!manifest.files||Object.keys(manifest.files).length<1||Object.keys(manifest.files).length>128||manifest.files['docs/portal-live-activation-review.md']!==manifest.reviewSha256||Object.keys(manifest.files).length!==Object.keys(current.files).length||Object.entries(manifest.files).some(([path,value])=>!hash(value)||current.files[path]!==value))throw Error();
  if(!Array.isArray(manifest.callbacks)||manifest.callbacks.length!==2||JSON.stringify(manifest.callbacks.map((c:any)=>c.clientId).sort())!==JSON.stringify(['copilot-consent-portal','copilot-studio-generic-oauth'])||manifest.callbacks.some((c:any)=>!hash(c.beforeHash)||!hash(c.afterHash)))throw Error();
 }catch{throw new PolicyError('configuration');}
}
export function portalActivationWindow(approval:any,existing:any,now=Date.now()){
 if(approval?.approved!==true||approval.scope!==scope||!hash(approval.reviewSha256)||!hash(approval.manifestSha256)||!Number.isSafeInteger(approval.approvedAt)||approval.approvedAt>now+5000||now-approval.approvedAt>86400000)throw new PolicyError('configuration');
 portalRunFiles(approval);
 if(approval.sessionPolicy!==undefined)portalSessionPolicy(approval.sessionPolicy);
 const window=existing??{schemaVersion:1,scope,reviewSha256:approval.reviewSha256,manifestSha256:approval.manifestSha256,...(approval.runId?{runId:approval.runId,runReviewSha256:approval.runReviewSha256}:{}),...(approval.sessionPolicy?{sessionPolicy:portalSessionPolicy(approval.sessionPolicy)}:{}),startedAt:now,expiresAt:now+3600000};
 if(JSON.stringify(window.sessionPolicy===undefined?undefined:portalSessionPolicy(window.sessionPolicy))!==JSON.stringify(approval.sessionPolicy===undefined?undefined:portalSessionPolicy(approval.sessionPolicy)))throw new PolicyError('configuration');
 if(window.runId!==approval.runId||window.runReviewSha256!==approval.runReviewSha256)throw new PolicyError('configuration');
 if(window.schemaVersion!==1||window.scope!==scope||window.reviewSha256!==approval.reviewSha256||window.manifestSha256!==approval.manifestSha256||!Number.isSafeInteger(window.startedAt)||window.startedAt<approval.approvedAt-5000||window.startedAt>now+5000||window.expiresAt!==window.startedAt+3600000||window.expiresAt<=now)throw new PolicyError('configuration');return window;
}
