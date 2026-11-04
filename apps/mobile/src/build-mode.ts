export function mobileMode(value:unknown):'device-test'|'live'{
 if(value===undefined)return'device-test';if(value==='device-test'||value==='live')return value;throw Error('invalid_mobile_build_mode');
}
export function mobileHtml(html:string,mode:'device-test'|'live'){
 const marker="connect-src 'none'";if(html.split(marker).length!==2)throw Error('invalid_mobile_content_policy');
 return mode==='live'?html.replace(marker,'connect-src https://agent.copilot.darkedges.com').replace('Federated Copilot — device test','Federated Copilot — live preview'):html;
}
