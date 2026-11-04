// Explicit verification only: no saved operations selection and no audit deletion.
import {startLocalToolService,currentOwnerSid} from './local-tool-service.mjs';
try{
 const service=await startLocalToolService({ownerSid:currentOwnerSid(),retentionDays:null});
 if(!process.send)throw Error('Verification IPC required');process.send({ready:true,instance:service.plan.instance});
 const result=await service.exited;if(!result.stopped)process.exitCode=1;
}catch{console.error('Controller verification worker failed');process.exitCode=1;}
