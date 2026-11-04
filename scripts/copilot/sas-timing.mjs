// Diagnostic arithmetic only: never return a URL, query value or authority decision.
export function sasTiming(value,now,providerDate){
 let expiry,format='unrecognized';
 if(typeof value!=='string'||value.length>64||!Number.isFinite(now))return{format};
 if(/^\d{10}$/.test(value)){expiry=Number(value)*1000;format='unix_seconds';}
 else if(/^\d{13}$/.test(value)){expiry=Number(value);format='unix_milliseconds';}
 else if(/^\d{18}$/.test(value)){expiry=Number((BigInt(value)-621355968000000000n)/10000n);format='dotnet_ticks';}
 else if(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/.test(value)){expiry=Date.parse(value);format='iso_utc';}
 if(!Number.isFinite(expiry)||Math.abs(expiry-now)>366*86400000)return{format:'unrecognized'};
 const provider=typeof providerDate==='string'?Date.parse(providerDate):NaN;
 return{format,hostRemainingSeconds:Math.round((expiry-now)/1000),...(Number.isFinite(provider)?{providerRemainingSeconds:Math.round((expiry-provider)/1000)}:{})};
}
