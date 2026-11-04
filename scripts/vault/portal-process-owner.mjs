import {execFileSync} from 'node:child_process';import {resolve} from 'node:path';
export function portalOwnerSid(){
 if(process.platform!=='win32'||!process.env.SystemRoot)throw Error('Selected Windows owner required');
 const output=execFileSync(resolve(process.env.SystemRoot,'System32/whoami.exe'),['/user','/fo','csv','/nh'],{encoding:'utf8',stdio:['ignore','pipe','ignore'],windowsHide:true,timeout:5000});
 const sid=output.match(/S-1-5-21-(?:\d+-){3}\d+/)?.[0];if(!sid)throw Error('Windows owner unavailable');return sid;
}
export function portalProcessPresent(pid){
 if(!Number.isSafeInteger(pid)||pid<1)throw Error('Invalid recorded process identity');
 try{process.kill(pid,0);return true;}catch(error){return error.code!=='ESRCH';}
}
