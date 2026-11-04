import {createHash} from 'node:crypto';
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const documentStageHash=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export function documentStageMatches(actual,expected,key=''){if(Array.isArray(expected)){if(!Array.isArray(actual))return false;if(['scopes','coreAttributes','extendedAttributes'].includes(key))return actual.length===expected.length&&expected.every(v=>typeof v?.name==='string'&&actual.filter(a=>a.name===v.name).length===1&&documentStageMatches(actual.find(a=>a.name===v.name),v));if(['fields','tables'].includes(key))return expected.every(v=>typeof v?.name==='string'&&actual.filter(a=>a.name===v.name).length===1&&documentStageMatches(actual.find(a=>a.name===v.name),v));return actual.length===expected.length&&expected.every((v,i)=>documentStageMatches(actual[i],v));}if(expected&&typeof expected==='object')return !!actual&&Object.entries(expected).every(([k,v])=>documentStageMatches(actual[k],v,k));return actual===expected;}
export async function documentStageStep({id,journal,save,read,write,expected,previousHash}){
 const entry=journal.steps[id];if(entry?.state==='pending')throw Error('document_stage_uncertain_write');
 const current=await read();
 if(entry?.state==='confirmed'){if(!current||documentStageHash(current)!==entry.hash)throw Error('document_stage_drift');return current;}
 if(current&&(!previousHash||documentStageHash(current)!==previousHash)||!current&&previousHash)throw Error('document_stage_foreign_object');
 journal.steps[id]={state:'pending',expectedHash:documentStageHash(expected)};save(journal);
 await write();const result=await read();if(!result||!documentStageMatches(result,expected))throw Error('document_stage_readback_failed');
 journal.steps[id]={state:'confirmed',hash:documentStageHash(result)};save(journal);return result;
}
