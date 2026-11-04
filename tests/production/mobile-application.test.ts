import test from 'node:test';import assert from 'node:assert/strict';
import {createMobileApplication} from '../../src/mobile/application.ts';
import {MobilePfExchange} from '../../src/mobile/pf-exchange.ts';
test('protected mobile application rejects incomplete or simulated leaf adapters at construction',()=>{assert.throws(()=>createMobileApplication({origin:'https://agent.example.test'},{}),/mobile_application_configuration/);assert.throws(()=>createMobileApplication({origin:'https://agent.example.test'},{mobile:{authorize:async()=>({sub:'human'})},resources:{},provider:{},oidc:{},chat:{mode:'mock'},documents:{},graph:{getToken:async()=>({value:'fake'})}}),/mobile_application_configuration/);});
