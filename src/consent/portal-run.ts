import {PolicyError} from '../policy/contracts.ts';
import {portalSessionPolicy,type PortalSessionPolicy} from './portal-session-policy.ts';
export type PortalRunPlan={reviewSha256:string;runId?:string;runReviewSha256?:string;mode?:'staged'|'live';sessionPolicy?:PortalSessionPolicy};
export function portalRunFiles(plan:PortalRunPlan){
 if(!/^[a-f0-9]{64}$/.test(plan.reviewSha256))throw new PolicyError('configuration');
 if(plan.mode==='staged'){if(plan.runId!==undefined||plan.runReviewSha256!==undefined||plan.sessionPolicy!==undefined)throw new PolicyError('configuration');return{journal:'journal.staged.sqlite',window:'activation-start.staged.json',reviewSha256:plan.reviewSha256};}
 if(plan.runId===undefined&&plan.runReviewSha256===undefined){if(plan.sessionPolicy!==undefined)throw new PolicyError('configuration');return{journal:'journal.sqlite',window:'activation-start.json',reviewSha256:plan.reviewSha256};}
 if(typeof plan.runId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(plan.runId)||typeof plan.runReviewSha256!=='string'||!/^[a-f0-9]{64}$/.test(plan.runReviewSha256)||plan.runReviewSha256===plan.reviewSha256)throw new PolicyError('configuration');
 if(plan.sessionPolicy!==undefined)portalSessionPolicy(plan.sessionPolicy);
 return{journal:`${plan.sessionPolicy?'sessions':'journal'}.${plan.runId}.sqlite`,window:`activation-start.${plan.runId}.json`,reviewSha256:plan.runReviewSha256};
}
