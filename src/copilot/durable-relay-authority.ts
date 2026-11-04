import {GatewayProofHandoff} from './relay-handoff.ts';
import {DurableRelayIssuer} from './durable-relay-issuer.ts';
import {RelayProofStore} from './relay-proof-store.ts';
import {fetchCustodyKey} from './relay-custody-key.mjs';
import {ProviderRelayError} from './provider-tool-relay.ts';

type HandoffConfig=ConstructorParameters<typeof GatewayProofHandoff>[0];
type HandoffDependencies=ConstructorParameters<typeof GatewayProofHandoff>[1];
type IssuerDependencies=ConstructorParameters<typeof DurableRelayIssuer>[1];
type Dependencies=Pick<HandoffDependencies,'brokerVerifier'|'agentVerifier'|'loginVerifier'|'authorise'|'audit'|'bindProvider'|'invalidateProvider'>&Pick<IssuerDependencies,'exchange'>;

// The composition root supplies its pinned TLS/mTLS Vault transport, never an
// endpoint, role, policy or secret selector from a request. No in-memory fallback.
export async function openDurableRelayAuthority(config:{handoff:HandoffConfig;databasePath:string;maxEntries:number},dependencies:Dependencies,vaultCall:Parameters<typeof fetchCustodyKey>[0]){
 const loaded=await fetchCustodyKey(vaultCall);let store:RelayProofStore|undefined;
 try{
  store=new RelayProofStore({path:config.databasePath,key:loaded.key,maxEntries:config.maxEntries});
  const custody=store;
  const issuer=new DurableRelayIssuer({brokerAudience:config.handoff.brokerAudience,scope:config.handoff.scope,agentAudience:config.handoff.agentAudience,loginIssuer:config.handoff.loginIssuer,additionalLoginIssuers:config.handoff.additionalLoginIssuers,loginAudience:config.handoff.loginAudience,timeoutMs:config.handoff.timeoutMs},{...dependencies,store:custody});
  const handoff=new GatewayProofHandoff(config.handoff,{...dependencies,reserveReplay:async(...args)=>custody.reserveReplay(...args),accept:async(...args)=>custody.accept(...args),commit:custody.commit.bind(custody),discard:async token=>custody.discard(token)});
  let closed=false;
  return{handoff,issuer,keyVersion:loaded.version,close(){if(closed)return;closed=true;issuer.close();custody.close();}};
 }catch{store?.close();throw new ProviderRelayError('configuration');}
 finally{loaded.key.fill(0);}
}
