import {readFileSync} from 'node:fs';import {resolve} from 'node:path';
import {load} from '../pf/common.mjs';import {custody} from './tool-custody.mjs';
// Portal PF B issuance uses the broker client, not the relay's tool client.
export function portalExecutorTrust(){return{authority:Object.fromEntries(Object.entries({pfAClientKeyPem:'consent-gateway-1',pfBClientKeyPem:'consent-gateway-2',policyAgentKeyPem:'policy-agent',policyGatewayKeyPem:'policy-gateway'}).map(([field,name])=>[field,load(name+'.jwks.json').keys[0]])),agentJwk:load('agent.jwks.json').keys[0],gateway:JSON.parse(readFileSync(resolve(custody,'relay-gateway-trust.json'),'utf8'))};}
