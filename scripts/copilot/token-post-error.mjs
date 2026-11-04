// Return only fixed categories; raw vendor text may echo tokens or SAS values.
export function tokenPostErrorMetadata(text){
 if(typeof text!=='string'||text.length>16384)return{category:'unclassified',jsonError:false};
 let jsonError=false;try{const value=JSON.parse(text);jsonError=!!value&&typeof value==='object'&&('error'in value||'message'in value);}catch{}
 let category='unclassified';
 for(const [name,pattern]of [['expired',/\bexpired\b/i],['missing_token',/\b(?:missing|required)\b.{0,25}\btoken\b|\btoken\b.{0,25}\b(?:missing|required)\b/i],['invalid_token',/\binvalid[_ ]token\b/i],['user_binding',/\b(?:user.?id|user binding)\b/i],['origin',/\borigin\b/i],['token_exchange_configuration',/\btoken exchange\b/i],['signature',/\b(?:hmac|signature)\b/i]])if(pattern.test(text)){category=name;break;}
 return{category,jsonError};
}
