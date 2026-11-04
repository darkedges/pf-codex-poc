export function enrolledNetworkPlan(input){
 if(!input||Object.keys(input).sort().join()!=='id,image'||! /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.id)||! /^sha256:[a-f0-9]{64}$/.test(input.image))throw Error('Invalid enrolled network plan');
 const network='fc-enrolled-'+input.id;
 return{network,internalSubnet:'10.236.250.16/28',bridgeName:'fc-enrolled-backend-'+input.id,toolName:'fc-enrolled-tool-'+input.id,label:'federated-copilot.enrolled-tool='+input.id,image:input.image,hostPorts:[],toolNetworks:[network],bridgeNetworks:['bridge',network],toolSecretFiles:['tool-server-key.pem','tool-server-cert.pem','tool-client-ca.pem','tool-outbound-ca.pem','tool-policy-key.pem','tool-audit-key'],mountOperatorCredentials:false,runAsUser:'1000:1000'};
}
