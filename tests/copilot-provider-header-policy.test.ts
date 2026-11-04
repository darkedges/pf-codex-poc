import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
test('connector forwards only the existing provider header on the fixed diagnostic request',()=>{
 const p=JSON.parse(readFileSync(new URL('../infra/copilot/provider-header-forwarding.apiProperties.json',import.meta.url),'utf8')).properties;
 assert.deepEqual(p.policyTemplateInstances,[{templateId:'setheader',title:'Forward signed-in provider token',parameters:{'x-ms-apimTemplateParameter.name':'X-PF-User-Access-Token','x-ms-apimTemplateParameter.value':"@headers('X-PF-User-Access-Token')",'x-ms-apimTemplateParameter.existsAction':'override','x-ms-apimTemplate-policySection':'Request','x-ms-apimTemplate-operationName':['VerifyDelegatedAccess']}}]);
 assert.equal(p.connectionParameters.api_key.type,'securestring');
 assert.equal(p.connectionParameters.api_key.uiDefinition.constraints.clearText,false);
 assert.equal(Object.keys(p.connectionParameters).join(),'api_key');
});
