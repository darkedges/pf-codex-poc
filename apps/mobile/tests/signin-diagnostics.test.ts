import test from 'node:test';import assert from 'node:assert/strict';
import {SignInDiagnostics} from '../src/signin-diagnostics.ts';
test('diagnostics retain bounded fixed events and ignore arbitrary fields, codes and HTTP details',()=>{
 const d=new SignInDiagnostics();d.begin();
 d.record('backend_login','failed',{code:'mobile_service_request_failed',httpStatus:401,message:'secret-token',url:'https://private/?secret=1'} as any);
 d.record('private-key-value' as any,'failed',{code:'private-token-value'} as any);
 for(let i=0;i<100;i++)d.record('app_background','passed',{code:'private-token-value',httpStatus:999} as any);
 const report=d.report();assert.ok(report.length<16000);assert.ok(!/secret-token|private-key|private-token|https:|url|message/.test(report));assert.equal(d.snapshot().events.length,48);
 d.begin();d.record('backend_login','failed',{code:'mobile_service_request_failed',httpStatus:401});assert.equal(d.snapshot().events.at(-1).httpStatus,401);
 const copy=d.snapshot();copy.events.length=0;assert.notEqual(d.snapshot().events.length,0);
});
