export function toolPolicyLease(seconds=28800){if(![3600,28800].includes(seconds))throw Error('Explicit bounded policy lease required');return seconds===3600?'1h':'8h';}
