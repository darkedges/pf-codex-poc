const stringToken=/"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
/** Flat string-only JSON, with duplicate keys checked after decoding escapes. */
export function parseMobileFields(raw:string,fields:string[]):Record<string,string>{
 if(typeof raw!=='string'||Buffer.byteLength(raw)>16000)throw Error('invalid_mobile_fields');
 let offset=0;const out:Record<string,string>=Object.create(null),seen=new Set<string>();
 const space=()=>{while(/[\x20\x09\x0a\x0d]/.test(raw[offset]??'!'))offset++;};
 const token=()=>{space();stringToken.lastIndex=offset;const m=stringToken.exec(raw);if(!m)throw Error();offset=stringToken.lastIndex;return JSON.parse(m[0]) as string;};
 space();if(raw[offset++]!=='{')throw Error();space();
 if(raw[offset]!=='}')while(true){const name=token();space();if(raw[offset++]!==':'||seen.has(name))throw Error();seen.add(name);out[name]=token();space();if(raw[offset]!==',')break;offset++;}
 if(raw[offset++]!=='}')throw Error();space();if(offset!==raw.length||Object.keys(out).sort().join()!==[...fields].sort().join())throw Error();return out;
}
