import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const action=readFileSync(new URL('../infra/copilot/verify-delegation.action.mcs.yml',import.meta.url),'utf8');
const topic=readFileSync(new URL('../infra/copilot/verify-delegation.topic.mcs.yml',import.meta.url),'utf8');
test('blocked draft topic cannot fetch a credential, invoke a tool or claim success',()=>{
 const blocked=readFileSync(new URL('../infra/copilot/verify-delegation.blocked.topic.mcs.yml',import.meta.url),'utf8');
 assert.doesNotMatch(blocked,/BeginDialog|InvokeConnector|AccessToken|SetVariable|LogCustomTelemetryEvent|activity: Delegated tool access verified\./);
 assert.match(blocked,/activity: Delegated tool access is not verified\./);
});
test('deployed diagnostic takes credentials only from the authenticated system variable',()=>{
 assert.match(action,/kind: ManualTaskInput\s+propertyName: PfUserAccessToken\s+value: =System\.User\.AccessToken/);
 assert.doesNotMatch(action,/AutomaticTaskInput|shouldPromptUser|System\.Activity|Topic\.|Global\./);
 assert.equal((action.match(/kind: ManualTaskInput/g)??[]).length,2);
});
test('diagnostic requires runtime sign-in and a true connector result; absence cannot report success',()=>{
 assert.match(topic,/condition: =System\.User\.IsLoggedIn = true/);
 assert.match(topic,/condition: =Topic\.Authorized = true/);
 assert.match(topic,/authorized: Topic\.Authorized/);
 assert.equal((topic.match(/activity: Delegated tool access verified\./g)??[]).length,1);
 assert.match(topic,/elseActions:[\s\S]*activity: Delegated tool access not verified\./);
 assert.match(topic,/activity: Sign in before verifying delegated tool access\./);
 assert.doesNotMatch(topic,/System\.User\.AccessToken|AutomaticTaskInput|LogCustomTelemetryEvent/);
});
test('deployed diagnostic fixes body and connector operation and returns only authorization',()=>{
 assert.match(action,/propertyName: body\s+value: =\{\}/);
 assert.match(action,/mode: Maker/);
 assert.match(action,/operationId: VerifyDelegatedAccess/);
 assert.match(action,/outputs:\s+- propertyName: authorized\s+action:/);
 assert.doesNotMatch(action,/access_token|client_secret|eyJ[A-Za-z0-9_-]+\./);
});
