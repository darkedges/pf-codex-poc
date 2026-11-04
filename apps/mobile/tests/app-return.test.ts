import test from 'node:test';import assert from 'node:assert/strict';
import {listenForMobileReturn} from '../src/app-return.ts';
const origin='https://agent.example.test',handoff='a'.repeat(42)+'A',url=origin+'/mobile/return?handoff='+handoff;
test('verified-shape Android return is delivered once across launch and foreground events',async()=>{
 let callback,calls=0,removed=false;const runtime={addListener:async(name,fn)=>{assert.equal(name,'appUrlOpen');callback=fn;return{remove:async()=>{removed=true;}};},getLaunchUrl:async()=>({url})};
 const close=await listenForMobileReturn(origin,async value=>{assert.equal(value,handoff);calls++;},runtime);
 callback({url});callback({url:'https://evil.test/mobile/return?handoff='+handoff});assert.equal(calls,1);await close();callback({url});assert.equal(calls,1);assert.equal(removed,true);
});
test('browser and malformed returns cannot masquerade as an Android sign-in',async()=>{await assert.rejects(listenForMobileReturn(origin,async()=>{}),/android_device_required/);let calls=0;const runtime={addListener:async()=>({remove:async()=>{}}),getLaunchUrl:async()=>({url:origin+'/mobile/return?token=private'})};const close=await listenForMobileReturn(origin,async()=>{calls++;},runtime);assert.equal(calls,0);await close();});
test('a newly started sign-in can ignore a stale original launch Intent',async()=>{let calls=0,reads=0,callback;const runtime={addListener:async(name,fn)=>{callback=fn;return{remove:async()=>{}};},getLaunchUrl:async()=>{reads++;return{url};}};const close=await listenForMobileReturn(origin,async()=>{calls++;},runtime,false);assert.equal(reads,0);assert.equal(calls,0);callback({url});assert.equal(calls,1);await close();});
