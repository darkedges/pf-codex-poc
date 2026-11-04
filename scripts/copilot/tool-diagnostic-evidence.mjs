// Project fixed metadata only. Never retain arbitrary bot text, response bodies or headers.
export function diagnosticMessageMarkers(messages){
 const text=new Set(messages.map(m=>m.text));
 const platformErrorReported=messages.some(m=>typeof m.text==='string'&&m.text.startsWith('An error has occurred.'));
 const allowed=['ConnectorAuthorizationError','ConnectorRequestFailure','ConnectorActionBadRequest','ConnectionNotFound','ConnectionAuthorizationFailed','ConnectionNotConfigured','InvalidInput','InvalidContent','DialogNotFound','ActionNotFound','InternalServerError'];
 const reported=messages.map(m=>typeof m.text==='string'?m.text.match(/(?:^|\n)Error code: ([A-Za-z][A-Za-z0-9_.]{0,80})(?:\n|$)/)?.[1]:undefined).find(code=>allowed.includes(code));
 return{connectorStarted:text.has('Delegated diagnostic stage: connector started.'),connectorReturned:text.has('Delegated diagnostic stage: connector returned.'),toolVerified:text.has('Delegated tool access verified.'),toolDenied:text.has('Delegated tool access not verified.'),platformErrorReported,...(platformErrorReported?{platformErrorCode:reported??'unclassified'}:{})};
}
export function diagnosticResponseMetadata(operation,response){
 if(!['token_post','activity_poll','channel_post'].includes(operation))throw Error('Invalid diagnostic operation');
 const requestId=response.headers.get('x-ms-request-id'),date=response.headers.get('date');
 return{operation,status:response.status,...(requestId&&/^[a-f0-9-]{16,64}$/i.test(requestId)?{requestId}:{}),...(date&&/^\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(date)?{serverDate:date}:{})};
}
