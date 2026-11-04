import test from 'node:test';import assert from 'node:assert/strict';
import {diagnosticMessageMarkers,diagnosticResponseMetadata} from '../scripts/copilot/tool-diagnostic-evidence.mjs';
test('stage evidence distinguishes entry, return, success and platform failure',()=>{
 assert.deepEqual(diagnosticMessageMarkers([{text:'Delegated diagnostic stage: connector started.'}]),{connectorStarted:true,connectorReturned:false,toolVerified:false,toolDenied:false,platformErrorReported:false});
 assert.equal(diagnosticMessageMarkers([{text:'Delegated diagnostic stage: connector returned.'},{text:'Delegated tool access verified.'}]).toolVerified,true);
 assert.equal(diagnosticMessageMarkers([{text:'An error has occurred.\nError code: synthetic'}]).platformErrorReported,true);
 assert.equal(diagnosticMessageMarkers([{text:'An error has occurred.\nError code: ConnectorRequestFailure\n'}]).platformErrorCode,'ConnectorRequestFailure');
 assert.equal(diagnosticMessageMarkers([{text:'An error has occurred.\nError code: ConnectorAuthorizationError\n'}]).platformErrorCode,'ConnectorAuthorizationError');
 assert.equal(diagnosticMessageMarkers([{text:'An error has occurred.\nError code: synthetic-private-value\n'}]).platformErrorCode,'unclassified');
});
test('untrusted bot text and credential-bearing headers never enter diagnostic evidence',()=>{
 const secret='synthetic-private-value';const markers=diagnosticMessageMarkers([{text:secret},{text:'Delegated tool access verified. '+secret}]);
 assert.equal(markers.toolVerified,false);assert.ok(!JSON.stringify(markers).includes(secret));
 const response=new Response(secret,{headers:{'x-ms-request-id':secret,'set-cookie':secret,'authorization':'Bearer '+secret,'date':secret}});
 assert.deepEqual(diagnosticResponseMetadata('token_post',response),{operation:'token_post',status:200});
 assert.throws(()=>diagnosticResponseMetadata(secret,response));
});
