import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { local, save, root } from './common.mjs';
import { redactLogConfig } from './logging-config.mjs';
const path = '/opt/out/instance/server/default/conf/log4j2.xml';
for (const node of ['a','b']) {
  const container = `federated-copilot-pf-pf-${node}-1`;
  const current = spawnSync('docker',['exec',container,'cat',path],{encoding:'utf8',maxBuffer:2_000_000});
  if (current.status !== 0) throw Error('Cannot read dedicated PF logging configuration');
  const transformed = redactLogConfig(current.stdout);
  if (transformed !== current.stdout) {
    save(`log4j2-${node}.xml`,transformed);
    const copy = spawnSync('docker',['cp',resolve(local,`log4j2-${node}.xml`),`${container}:${path}`],{cwd:root,stdio:'inherit'});
    if (copy.status !== 0) throw Error('Cannot install PF logging redaction');
    // PF monitors this file, but restart makes the protection deterministic before token tests.
    const restart = spawnSync('docker',['restart',container],{cwd:root,stdio:'inherit'});
    if (restart.status !== 0) throw Error('Cannot activate PF logging redaction');
  }
  console.log(`PF ${node}: JWT log redaction installed`);
}
