// A separate allowance; never reset or reuse a historical sign-in budget.
export function toolAttemptFiles(mode){
 const first='live-sso-tool-diagnostic-1-budget.json',second='live-sso-tool-diagnostic-followup-1-budget.json';
 if(mode==='--run')return{budget:first,approval:'approval.json',publication:'publication-confirmation.json',previous:[]};
 if(mode==='--run-followup-1')return{budget:second,approval:'followup-1-approval.json',publication:'publication-followup-1-confirmation.json',previous:[first]};
 if(mode==='--run-simple-header-1')return{budget:'live-sso-tool-diagnostic-simple-header-1-budget.json',approval:'simple-header-1-approval.json',publication:'publication-simple-header-1-confirmation.json',previous:[first,second],reviewDocument:'docs/microsoft-tool-simple-header-test-review.md'};
 throw Error('Unknown tool attempt');
}
export function consumeToolAttempt(state,event){
 if(!state||Object.keys(state).sort().join()!=='conversations,tokenPosts'||![0,1].includes(state.conversations)||![0,1].includes(state.tokenPosts)||state.tokenPosts>state.conversations)throw Error('Invalid tool attempt allowance');
 const next={...state};
 if(event==='conversation'&&next.conversations===0&&next.tokenPosts===0)next.conversations=1;
 else if(event==='tokenPost'&&next.conversations===1&&next.tokenPosts===0)next.tokenPosts=1;
 else throw Error('Tool attempt allowance consumed');
 return next;
}
