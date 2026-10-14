import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');

const config = JSON.parse(
  await readFile(resolve(root, 'aleph.config.json'), 'utf8')
);

if (!Number.isInteger(config.step) || config.step < 1 || config.step > 12) {
  throw new Error('단계 설정을 확인하세요.');
}

const data = JSON.parse(await readFile(source, 'utf8'));

if (!Array.isArray(data.notes)) {
  throw new Error('자료 형식이 올바르지 않습니다.');
}

await mkdir(resolve(root, 'public'), { recursive: true });

// Bundle the pinned browser WebAuthn client locally: no remote script or key storage.
await copyFile(
  resolve(root, 'node_modules', '@simplewebauthn', 'browser', 'dist', 'bundle', 'index.umd.min.js'),
  resolve(root, 'public', 'webauthn.js')
);

if (config.step === 1) {
  await copyFile(source, output);
} else {
  if (data.notes.length !== 0) {
    throw new Error('공개 data.json에 메모가 남아 있습니다.');
  }

  await rm(output, { force: true });
}

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);

  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8'
  );
}
