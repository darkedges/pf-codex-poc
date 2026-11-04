// Defense-in-depth projection before persisting IPC observations. Never serialize the input.
const states=new Set(['missing','multiple','oversized','malformed','present']);
export function projectRelayHttpDiagnostic(value){
 if(value?.event!=='provider_relay_http'||!Number.isInteger(value.status)||value.status<100||value.status>599||!states.has(value.credentials?.provider)||!states.has(value.credentials?.caller))return undefined;
 return{event:'provider_relay_http',status:value.status,credentials:{provider:value.credentials.provider,caller:value.credentials.caller}};
}
