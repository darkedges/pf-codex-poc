// Diagnostic IPC may arrive before readiness; it must not decide startup success.
export function waitForRelayReady(child,instance,timeoutMs=20000){
 return new Promise((resolve,reject)=>{
  const finish=ok=>{clearTimeout(timer);child.removeListener('message',message);child.removeListener('error',failed);child.removeListener('exit',failed);ok?resolve():reject(Error('Managed relay readiness unavailable'));};
  const message=value=>{if(value?.ready===true&&value.instance===instance)finish(true);else if(value?.failed===true)finish(false);},failed=()=>finish(false);
  const timer=setTimeout(failed,timeoutMs);child.on('message',message);child.once('error',failed);child.once('exit',failed);
 });
}
