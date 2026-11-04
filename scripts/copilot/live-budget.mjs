export function reserveConversation(budget,mode){
 const modes=['interactive','autonomous'];
 if(budget?.max!==2||!Array.isArray(budget.reserved)||budget.reserved.length>=2||budget.reserved.some(m=>!modes.includes(m))||new Set(budget.reserved).size!==budget.reserved.length||!modes.includes(mode)||budget.reserved.includes(mode))throw Error('Live conversation budget exhausted or invalid');
 return{max:2,reserved:[...budget.reserved,mode]};
}
export function reserveTimingFollowup(original,followup){
 if(original?.max!==2||!Array.isArray(original.reserved)||original.reserved.length!==2||!original.reserved.includes('interactive')||!original.reserved.includes('autonomous')||followup?.max!==1||!Array.isArray(followup.reserved)||followup.reserved.length)throw Error('Timing follow-up budget used or invalid');
 return{max:1,reserved:['interactive']};
}
export function reserveOperatorRetry(original,timing,retry){
 // Revalidate original history without changing either previous reservation.
 reserveTimingFollowup(original,{max:1,reserved:[]});
 if(timing?.max!==1||!Array.isArray(timing.reserved)||timing.reserved.length!==1||timing.reserved[0]!=='interactive'||retry?.max!==1||!Array.isArray(retry.reserved)||retry.reserved.length)throw Error('Operator retry budget used or invalid');
 return{max:1,reserved:['interactive']};
}
export function reserveProviderCapture(history,budget){
 if(!Array.isArray(history)||history.length!==3)throw Error('Provider capture history invalid');
 reserveOperatorRetry(history[0],history[1],{max:1,reserved:[]});
 if(history[2]?.max!==1||JSON.stringify(history[2].reserved)!=='["interactive"]'||budget?.max!==1||budget.purpose!=='configured-provider-capture'||!Array.isArray(budget.reserved)||budget.reserved.length)throw Error('Provider capture allowance exhausted or invalid');
 return{max:1,reserved:['interactive'],purpose:'configured-provider-capture'};
}
export function reserveRetainedProviderCapture(history,previous,budget){
 reserveProviderCapture(history,{max:1,reserved:[],purpose:'configured-provider-capture'});
 if(previous?.max!==1||previous.purpose!=='configured-provider-capture'||JSON.stringify(previous.reserved)!=='["interactive"]'||budget?.max!==1||budget.purpose!=='configured-provider-vault-capture'||!Array.isArray(budget.reserved)||budget.reserved.length)throw Error('Retained capture allowance exhausted or invalid');
 return{max:1,reserved:['interactive'],purpose:'configured-provider-vault-capture'};
}
export function reservePublishedProviderCapture(history,previous,retained,budget){
 reserveRetainedProviderCapture(history,previous,{max:1,reserved:[],purpose:'configured-provider-vault-capture'});
 if(retained?.max!==1||retained.purpose!=='configured-provider-vault-capture'||JSON.stringify(retained.reserved)!=='["interactive"]'||budget?.max!==1||budget.purpose!=='published-provider-vault-capture'||!Array.isArray(budget.reserved)||budget.reserved.length)throw Error('Published capture allowance exhausted or invalid');
 return{max:1,reserved:['interactive'],purpose:'published-provider-vault-capture'};
}
export function reserveLongerProviderCapture(history,previous,retained,published,budget){
 reservePublishedProviderCapture(history,previous,retained,{max:1,reserved:[],purpose:'published-provider-vault-capture'});
 if(published?.max!==1||published.purpose!=='published-provider-vault-capture'||JSON.stringify(published.reserved)!=='["interactive"]'||budget?.max!==1||budget.purpose!=='longer-provider-vault-capture'||!Array.isArray(budget.reserved)||budget.reserved.length)throw Error('Longer-token capture allowance exhausted or invalid');
 return{max:1,reserved:['interactive'],purpose:'longer-provider-vault-capture'};
}
export function reserveHourProviderCapture(history,previous,retained,published,longer,budget){
 reserveLongerProviderCapture(history,previous,retained,published,{max:1,reserved:[],purpose:'longer-provider-vault-capture'});
 if(longer?.max!==1||longer.purpose!=='longer-provider-vault-capture'||JSON.stringify(longer.reserved)!=='["interactive"]'||budget?.max!==1||budget.purpose!=='hour-provider-vault-capture'||!Array.isArray(budget.reserved)||budget.reserved.length)throw Error('One-hour capture allowance exhausted or invalid');
 return{max:1,reserved:['interactive'],purpose:'hour-provider-vault-capture'};
}
