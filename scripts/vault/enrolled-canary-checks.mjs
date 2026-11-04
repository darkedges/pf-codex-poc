import {profile} from '../pf/config.mjs';
export function validateCanaryClaims(c,id,mode){return !!c&&c.sub===profile.human&&c.act?.sub===profile.agent&&c.act?.iss===profile.agentIssuer&&c.org_id===profile.org&&c.delegation_id===id&&c.execution_mode===mode&&c.iss==='https://pf-b.copilot.darkedges.com'&&c.aud==='api://copilot-tool'&&c.scope===profile.scope&&Number.isInteger(c.iat)&&Number.isInteger(c.exp)&&c.exp>c.iat&&c.exp-c.iat<=120;}
export function canaryTerminalState(before,after,owned){
 if(new Set(owned).size!==owned.length||before.some(r=>owned.includes(r.id))||after.length!==before.length+owned.length)return false;
 return before.every(r=>after.some(a=>a.id===r.id&&a.state===r.state&&a.version===r.version))&&owned.every(id=>after.some(a=>a.id===id&&a.state==='revoked'&&a.version>=2));
}
export async function revokeOwnedCanaryGrant(state,revoke){
 for(let attempt=0;attempt<3;attempt++){
  const current=state();if(current==='revoked')return;if(current!=='active')throw Error('Owned grant state unavailable');
  try{await revoke();}catch{}
  if(state()==='revoked')return;
 }
 throw Error('Owned grant revocation unconfirmed');
}
