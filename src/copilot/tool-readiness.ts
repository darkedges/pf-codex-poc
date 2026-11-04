import {performance} from 'node:perf_hooks';
type Options={checks:((signal:AbortSignal)=>Promise<boolean>)[];timeoutMs:number;cacheMs:number;now?:()=>number};
export class ToolReadiness {
 private options:Options;private pending?:Promise<boolean>;private cached?:boolean;private at=-Infinity;
 constructor(options:Options){
  if(!options.checks.length||!options.checks.every(c=>typeof c==='function')||!Number.isInteger(options.timeoutMs)||options.timeoutMs<100||options.timeoutMs>5000||!Number.isInteger(options.cacheMs)||options.cacheMs<0||options.cacheMs>1000)throw Error('Invalid tool readiness configuration');
  this.options={...options,checks:[...options.checks],now:options.now??(()=>performance.now())};
 }
 async check():Promise<boolean>{
  if(this.pending)return this.pending;
  if(this.cached!==undefined&&this.options.now!()-this.at<this.options.cacheMs)return this.cached;
  this.pending=(async()=>{
   const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
   try{
    const value=await Promise.race([Promise.all(this.options.checks.map(c=>Promise.resolve().then(()=>c(controller.signal)))).then(values=>values.every(v=>v===true)),new Promise<boolean>(done=>{timer=setTimeout(()=>{controller.abort();done(false);},this.options.timeoutMs);})]);
    this.cached=value;return value;
   }catch{this.cached=false;return false;}
   finally{if(timer)clearTimeout(timer);controller.abort();this.at=this.options.now!();}
  })();
  try{return await this.pending;}finally{this.pending=undefined;}
 }
}
