import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { test } from 'node:test';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import {
  beginRegistration, beginVerification, deviceStatus,
  finishRegistration, finishVerification, requireApprovedDevice,
} from '../src/device-access.mjs';

const config = { publicAppUrl: 'https://vault-test.vercel.app' };
const origin = 'https://vault-test.vercel.app';
const user = { kind: 'student', userId: '00000000-0000-4000-8000-000000000011' };
const secret = randomBytes(48).toString('hex');
const encode = value => Buffer.from(value).toString('base64url');

function mockDatabase() {
  let saved = { id: user.userId, app_metadata: { provider: 'email' } };
  const other = { id: '00000000-0000-4000-8000-000000000022', app_metadata: { provider: 'email' } };
  return {
    auth: { admin: {
      async getUserById(id) {
        const match = id === saved.id ? saved : id === other.id ? other : null;
        return { data: { user: match && structuredClone(match) }, error: null };
      },
      async updateUserById(id, changes) {
        if (id !== saved.id) return { error: new Error('wrong user') };
        saved = { ...saved, app_metadata: structuredClone(changes.app_metadata) };
        return { data: { user: structuredClone(saved) }, error: null };
      },
    } },
    revoke() { saved.app_metadata.alephVaultDevicesV1 = []; },
    get metadata() { return saved.app_metadata; },
  };
}

function mockResponse() {
  const headers = new Map();
  return {
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    getHeader(name) { return headers.get(name.toLowerCase()); },
  };
}

function getCookie(res, name) {
  const cookies = [res.getHeader('Set-Cookie')].flat().filter(Boolean);
  const cookie = cookies.find(item => item.startsWith(`${name}=`) && !item.includes('Max-Age=0'));
  assert.ok(cookie, `missing ${name} cookie`);
  return cookie.split(';')[0];
}

const requestWith = cookie => ({ headers: { cookie } });

function registrationResponse(challenge, privateKeyPair, credentialId, returnedOrigin = origin) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create',
    challenge, origin: returnedOrigin }));
  const { publicKey } = privateKeyPair;
  const jwk = publicKey.export({ format: 'jwk' });
  const coseKey = encodeCBOR(new Map([
    [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
  const authData = Buffer.concat([
    createHash('sha256').update(new URL(origin).hostname).digest(),
    Buffer.from([0x45, 0, 0, 0, 0]), // user present + verified + attested credential
    Buffer.alloc(16), // AAGUID
    Buffer.from([0, credentialId.length]), credentialId,
    Buffer.from(coseKey),
  ]);
  const attestationObject = encodeCBOR(new Map([
    ['fmt', 'none'], ['attStmt', new Map()], ['authData', authData],
  ]));
  const id = encode(credentialId);
  return { id, rawId: id, type: 'public-key', response: {
    clientDataJSON: encode(clientDataJSON),
    attestationObject: encode(attestationObject), transports: ['internal'],
  } };
}

function assertionResponse(challenge, privateKey, credentialId, count = 1) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(new URL(origin).hostname).digest(),
    Buffer.from([0x05, 0, 0, 0, count]), // user present + verified, new counter
  ]);
  const signature = sign('sha256', Buffer.concat([
    authenticatorData, createHash('sha256').update(clientDataJSON).digest(),
  ]), privateKey);
  const id = encode(credentialId);
  return { id, rawId: id, type: 'public-key', response: {
    clientDataJSON: encode(clientDataJSON),
    authenticatorData: encode(authenticatorData), signature: encode(signature),
    userHandle: null,
  } };
}

test('pending device cannot read; a verified device may read; revoked device is denied', async () => {
  const db = mockDatabase();
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const credentialId = randomBytes(32);
  const noCookie = requestWith('');
  const base = { user, db, secret };
  assert.deepEqual(await deviceStatus({ ...base, req: noCookie }), {
    approved: false, registered: false, expiresAt: null,
  });

  const beginRes = mockResponse();
  const begin = await beginRegistration({ ...base, res: beginRes, config });
  assert.equal(begin.status, 200);
  assert.equal(await requireApprovedDevice({ ...base, req: noCookie }), false);
  assert.equal(db.metadata.provider, 'email');
  const challengeReq = requestWith(getCookie(beginRes, '__Host-aleph-device-challenge'));

  const wrongOrigin = await finishRegistration({ ...base, config, req: challengeReq,
    res: mockResponse(), response: registrationResponse(begin.body.options.challenge,
      keys, credentialId, 'https://other.example') });
  assert.equal(wrongOrigin.status, 403);
  assert.equal(await requireApprovedDevice({ ...base, req: noCookie }), false);

  const approvedRes = mockResponse();
  const approved = await finishRegistration({ ...base, config, req: challengeReq,
    res: approvedRes, response: registrationResponse(begin.body.options.challenge, keys, credentialId) });
  assert.deepEqual(approved, { status: 200, body: { approved: true } });
  const cookie = getCookie(approvedRes, '__Host-aleph-device-access');
  assert.equal(await requireApprovedDevice({ ...base, req: requestWith(cookie) }), true);
  assert.equal(await requireApprovedDevice({ ...base, req: requestWith(`${cookie}tampered`) }), false);
  assert.equal(await requireApprovedDevice({ ...base, req: noCookie }), false);
  assert.equal(await requireApprovedDevice({ ...base, req: requestWith(cookie),
    user: { ...user, userId: '00000000-0000-4000-8000-000000000022' } }), false);
  assert.equal((await finishRegistration({ ...base, config, req: challengeReq,
    res: mockResponse(), response: registrationResponse(begin.body.options.challenge, keys, credentialId) })).status, 403);

  assert.deepEqual(await beginRegistration({ ...base, config, req: noCookie,
    res: mockResponse() }), { status: 403, body: { error: 'APPROVED_DEVICE_REQUIRED' } });
  assert.equal((await beginRegistration({ ...base, config, req: requestWith(cookie),
    res: mockResponse() })).status, 200);

  const verificationRes = mockResponse();
  const verification = await beginVerification({ ...base, res: verificationRes, config });
  assert.equal(verification.status, 200);
  const assertion = assertionResponse(verification.body.options.challenge, keys.privateKey, credentialId);
  const verifiedRes = mockResponse();
  const verified = await finishVerification({ ...base, config,
    req: requestWith(getCookie(verificationRes, '__Host-aleph-device-challenge')),
    res: verifiedRes, response: assertion });
  assert.deepEqual(verified, { status: 200, body: { approved: true } });
  assert.equal(db.metadata.alephVaultDevicesV1[0].counter, 1);
  assert.equal(await requireApprovedDevice({ ...base, req: requestWith(getCookie(verifiedRes,
    '__Host-aleph-device-access')) }), true);
  db.revoke();
  assert.equal(await requireApprovedDevice({ ...base, req: requestWith(cookie) }), false);
});
