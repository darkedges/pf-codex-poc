// Diagnostic projection only. These comparisons never authorize a read and must
// not be used to substitute a metadata reference for the configured site IDs.
export function inspectParentSiteShape(value:unknown,expectedSiteId:string){
 const expected=expectedSiteId.split(',');if(expected.length!==3)throw Error('Invalid diagnostic target');
 const guid=(v:string)=>/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(v),host=(v:string)=>/^[a-z0-9-]+\.sharepoint\.com$/i.test(v),equivalent=(a:string,b:string)=>a.toLowerCase()===b.toLowerCase();
 const result={shape:'other',compositeMatches:false,matchesSiteCollectionGuid:false,matchesWebGuid:false,hostMatches:false,siteCollectionMatches:false,webMatches:false,encodedCompositeMatches:false};
 if(value===undefined||value===null)return{...result,shape:'missing'};if(typeof value!=='string')return{...result,shape:'non_string'};if(!value)return{...result,shape:'empty'};if(value.length>2048)return{...result,shape:'oversized'};
 if(guid(value))return{...result,shape:'guid',matchesSiteCollectionGuid:equivalent(value,expected[1]),matchesWebGuid:equivalent(value,expected[2])};
 const parts=value.split(',');if(parts.length===3&&host(parts[0])&&guid(parts[1])&&guid(parts[2]))return{...result,shape:'composite',compositeMatches:equivalent(value,expectedSiteId),hostMatches:equivalent(parts[0],expected[0]),siteCollectionMatches:equivalent(parts[1],expected[1]),webMatches:equivalent(parts[2],expected[2])};
 if(/%2c/i.test(value)){try{const decoded=decodeURIComponent(value),p=decoded.split(',');if(p.length===3&&host(p[0])&&guid(p[1])&&guid(p[2]))return{...result,shape:'encoded_composite',encodedCompositeMatches:equivalent(decoded,expectedSiteId)};}catch{}}
 if(/^https?:\/\//i.test(value))return{...result,shape:'url'};return result;
}
