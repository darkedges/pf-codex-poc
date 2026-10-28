import test from 'node:test';
import assert from 'node:assert/strict';
import { createGateway2Exchange } from '../src/adapters/gateway-2.ts';

test('mock selection requires explicit demo authority and refuses production', async () => {
  const demo = process.env.DEMO_ONLY;
  const environment = process.env.NODE_ENV;
  try {
    delete process.env.DEMO_ONLY;
    await assert.rejects(createGateway2Exchange({ mode: 'mock' }));
    process.env.DEMO_ONLY = 'true';
    process.env.NODE_ENV = 'production';
    await assert.rejects(createGateway2Exchange({ mode: 'mock' }));
    process.env.NODE_ENV = 'test';
    assert.equal(typeof (await createGateway2Exchange({ mode: 'mock' })).exchange, 'function');
  } finally {
    if (demo === undefined) delete process.env.DEMO_ONLY; else process.env.DEMO_ONLY = demo;
    if (environment === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = environment;
  }
});
