import test from 'node:test';import assert from 'node:assert/strict';
import config from '../capacitor.config.ts';
test('bridge logging and WebView debugging are disabled before credential-bearing native operations',()=>{assert.equal(config.loggingBehavior,'none');assert.equal(config.android?.loggingBehavior,'none');assert.equal(config.android?.webContentsDebuggingEnabled,false);assert.equal(config.android?.allowMixedContent,false);assert.equal(config.server?.cleartext,false);});
