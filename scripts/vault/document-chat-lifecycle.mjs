// Every callback controls an owned resource only. A failed cleanup is retained,
// never converted to success or retried implicitly by a second stop request.
export function createDocumentChatLifecycle(deps){
 let retirement,stopping;
 const all=async(operations)=>{let failed=false;for(const operation of operations)try{await operation();}catch{failed=true;}if(failed)throw Error('document_chat_cleanup_required');};
 const retireAuthority=()=>retirement??=all([deps.releasePf,deps.stopDocumentPolicy,deps.stopOwnedChatPolicy]);
 return{retireAuthority,stop:()=>stopping??=all([deps.abort,deps.stopWorker,deps.stopRuntime,retireAuthority])};
}
