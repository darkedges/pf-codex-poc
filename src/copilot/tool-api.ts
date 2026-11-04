import {PolicyProtectedTool,ToolAccessError} from './tool-authority.ts';

export type ToolApiInput={method:string;path:string;authorization:string;rawBody:string};
export type ToolApiResponse={status:number;body:Record<string,unknown>};

// Exactly one administrator-composed read-only diagnostic. There is no request
// parameter that selects an identity, capability, URL, resource or operation.
export class ToolApi {
  private tool:PolicyProtectedTool<{authorized:boolean}>;
  constructor(tool:PolicyProtectedTool<{authorized:boolean}>){
    if(!(tool instanceof PolicyProtectedTool))throw new ToolAccessError('configuration');
    this.tool=tool;
  }
  async handle(input:ToolApiInput):Promise<ToolApiResponse>{
    const bearer=/^Bearer ([^\s]{1,16000})$/.exec(input.authorization);
    if(!bearer)return{status:401,body:{error:'invalid_token'}};
    if(input.method!=='POST'||input.path!=='/v1/tools/verify-access'||Buffer.byteLength(input.rawBody)>1024)return{status:400,body:{error:'invalid_request'}};
    try{
      const body=JSON.parse(input.rawBody);
      if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length)return{status:400,body:{error:'invalid_request'}};
    }catch{return{status:400,body:{error:'invalid_request'}};}
    try{
      const result=await this.tool.execute(bearer[1]);
      if(result?.authorized!==true)throw new ToolAccessError('tool_failed');
      // Never serialize arbitrary callback data or token claims into a response.
      return{status:200,body:{authorized:true}};
    }catch(error){
      const code=error instanceof ToolAccessError?error.code:'tool_failed';
      return{status:code==='invalid_token'?401:code==='policy_denied'?403:503,body:{error:code==='configuration'?'tool_failed':code}};
    }
  }
}
