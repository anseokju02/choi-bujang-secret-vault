import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const CHALLENGE_COOKIE = '__Host-aleph-device-challenge';
const ACCESS_COOKIE = '__Host-aleph-device-access';
const METADATA_KEY = 'alephVaultDevicesV1';
const PENDING_KEY = 'alephVaultPendingV1';
const CHALLENGE_SECONDS = 300;
const ACCESS_SECONDS = 900;
const MAX_DEVICES = 5;
const BASE64URL = /^[A-Za-z0-9_-]{8,1024}$/u;

function cookieValue(req, name) {
  const entry = (req.headers.cookie ?? '').split(';').map(item => item.trim())
    .find(item => item.startsWith(`${name}=`));
  return entry?.slice(name.length + 1) ?? null;
}

function signature(data, secret) {
  return createHmac('sha256', secret).update(`aleph.device.v1.${data}`)
    .digest('base64url');
}

function signed(value, secret) {
  const data = Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${data}.${signature(data, secret)}`;
}

function verifiedCookie(req, name, secret, now = Date.now()) {
  const raw = cookieValue(req, name);
  if (!raw || raw.length > 4096) return null;
  const [data, mac, extra] = raw.split('.');
  if (!data || !mac || extra) return null;
  const expected = Buffer.from(signature(data, secret));
  const actual = Buffer.from(mac);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const value = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    return Number.isSafeInteger(value.exp) && value.exp > Math.floor(now / 1000)
      ? value : null;
  } catch {
    return null;
  }
}

function appendCookie(res, value) {
  const previous = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', previous ? [...[previous].flat(), value] : value);
}

function setCookie(res, name, value, age) {
  appendCookie(res, `${name}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`);
}

export function clearDeviceCookies(res) {
  setCookie(res, ACCESS_COOKIE, '', 0);
  setCookie(res, CHALLENGE_COOKIE, '', 0);
}

function deviceOrigin(config) {
  const origin = new URL(config.publicAppUrl);
  if (origin.protocol !== 'https:' || !origin.hostname.endsWith('.vercel.app')
      || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('DEVICE_ORIGIN_NOT_CONFIGURED');
  }
  return { origin: origin.origin, rpID: origin.hostname };
}

function registeredDevices(user) {
  const devices = user?.app_metadata?.[METADATA_KEY];
  if (devices === undefined) return [];
  if (!Array.isArray(devices) || devices.length > MAX_DEVICES || devices.some(item =>
    !item || typeof item !== 'object' || !BASE64URL.test(item.id ?? '')
    || !BASE64URL.test(item.publicKey ?? '')
    || !Number.isSafeInteger(item.counter) || item.counter < 0
    || item.status !== 'approved')) {
    throw new Error('INVALID_DEVICE_REGISTRY');
  }
  return devices;
}

async function account(db, user) {
  if (user?.kind !== 'student') return null;
  const { data, error } = await db.auth.admin.getUserById(user.userId);
  if (error || !data?.user || data.user.id !== user.userId) {
    throw new Error('DEVICE_REGISTRY_UNAVAILABLE');
  }
  return data.user;
}

function getSecret(secret) {
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error('DEVICE_SERVER_KEY_UNAVAILABLE');
  }
  return secret;
}

function proof(req, secret, userId, deviceIds) {
  const value = verifiedCookie(req, ACCESS_COOKIE, secret);
  return value?.type === 'access' && value.userId === userId
    && deviceIds.some(item => item.id === value.credentialId) ? value : null;
}

export async function deviceStatus({ req, user, db, secret }) {
  const accountUser = await account(db, user);
  if (!accountUser) return { approved: false, registered: false, expiresAt: null };
  const devices = registeredDevices(accountUser);
  const deviceProof = proof(req, getSecret(secret), user.userId, devices);
  return {
    approved: Boolean(deviceProof),
    registered: devices.length > 0,
    expiresAt: deviceProof?.exp ?? null,
  };
}

export async function requireApprovedDevice({ req, user, db, secret }) {
  return (await deviceStatus({ req, user, db, secret })).approved;
}

function challengeFor(req, secret, user, type) {
  const challenge = verifiedCookie(req, CHALLENGE_COOKIE, secret);
  if (challenge?.type !== type || challenge.userId !== user.userId
      || !BASE64URL.test(challenge.challenge ?? '')) return null;
  return challenge.challenge;
}

function issueChallenge(res, secret, user, type, challenge) {
  const exp = Math.floor(Date.now() / 1000) + CHALLENGE_SECONDS;
  setCookie(res, CHALLENGE_COOKIE, signed({ type, userId: user.userId, challenge, exp }, secret), CHALLENGE_SECONDS);
}

function matchingPending(accountUser, type, challenge) {
  const pending = accountUser?.app_metadata?.[PENDING_KEY];
  return pending?.type === type && pending.exp > Math.floor(Date.now() / 1000)
    && pending.challengeHash === createHash('sha256').update(challenge).digest('hex');
}

function issueAccess(res, secret, user, credentialId) {
  const exp = Math.floor(Date.now() / 1000) + ACCESS_SECONDS;
  setCookie(res, ACCESS_COOKIE, signed({ type: 'access', userId: user.userId,
    credentialId, exp }, secret), ACCESS_SECONDS);
}

async function saveMetadata(db, user, accountUser, changes) {
  const { data, error } = await db.auth.admin.updateUserById(user.userId, {
    app_metadata: { ...accountUser.app_metadata, ...changes },
  });
  if (error || !data?.user) throw new Error('DEVICE_REGISTRY_UNAVAILABLE');
}

async function rememberPending(db, user, accountUser, type, challenge) {
  await saveMetadata(db, user, accountUser, {
    [PENDING_KEY]: { type, challengeHash: createHash('sha256').update(challenge).digest('hex'),
      exp: Math.floor(Date.now() / 1000) + CHALLENGE_SECONDS },
  });
}

// Register is a server-side policy: an existing authenticated account, a fresh
// server challenge, correct site origin, and authenticator user verification.
// The browser's installation status or an "approve" button is never trusted.
export async function beginRegistration({ req, res, user, db, secret, config }) {
  const accountUser = await account(db, user);
  if (!accountUser) return { status: 403, body: { error: 'DEVICE_REGISTRATION_UNAVAILABLE' } };
  const devices = registeredDevices(accountUser);
  if (devices.length && !proof(req, getSecret(secret), user.userId, devices)) {
    return { status: 403, body: { error: 'APPROVED_DEVICE_REQUIRED' } };
  }
  if (devices.length >= MAX_DEVICES) return { status: 409, body: { error: 'DEVICE_LIMIT_REACHED' } };
  const { rpID } = deviceOrigin(config);
  const options = await generateRegistrationOptions({
    rpName: 'BYTE BACK 보호 자료실', rpID,
    userID: new TextEncoder().encode(user.userId),
    userName: user.userId,
    attestationType: 'none',
    authenticatorSelection: { authenticatorAttachment: 'platform',
      residentKey: 'preferred', userVerification: 'required' },
    excludeCredentials: devices.map(item => ({ id: item.id, transports: item.transports })),
  });
  await rememberPending(db, user, accountUser, 'register', options.challenge);
  issueChallenge(res, getSecret(secret), user, 'register', options.challenge);
  return { status: 200, body: { options } };
}

export async function finishRegistration({ req, res, user, db, secret, config, response }) {
  const challenge = challengeFor(req, getSecret(secret), user, 'register');
  if (!challenge) return { status: 403, body: { error: 'DEVICE_CHALLENGE_REQUIRED' } };
  setCookie(res, CHALLENGE_COOKIE, '', 0);
  let verification;
  try {
    const { origin, rpID } = deviceOrigin(config);
    verification = await verifyRegistrationResponse({
      response, expectedChallenge: challenge, expectedOrigin: origin,
      expectedRPID: rpID, requireUserVerification: true,
    });
  } catch {
    return { status: 403, body: { error: 'DEVICE_PROOF_INVALID' } };
  }
  if (!verification.verified || !verification.registrationInfo) {
    return { status: 403, body: { error: 'DEVICE_PROOF_INVALID' } };
  }
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  // A synced passkey alone is not evidence for one particular physical device.
  if (credentialDeviceType !== 'singleDevice' || credentialBackedUp) {
    return { status: 403, body: { error: 'DEVICE_BOUND_KEY_REQUIRED' } };
  }
  const accountUser = await account(db, user);
  if (!matchingPending(accountUser, 'register', challenge)) {
    return { status: 403, body: { error: 'DEVICE_CHALLENGE_REQUIRED' } };
  }
  const devices = registeredDevices(accountUser);
  if (devices.length && !proof(req, getSecret(secret), user.userId, devices)) {
    return { status: 403, body: { error: 'APPROVED_DEVICE_REQUIRED' } };
  }
  if (devices.length >= MAX_DEVICES || devices.some(item => item.id === credential.id)) {
    return { status: 409, body: { error: 'DEVICE_ALREADY_REGISTERED' } };
  }
  await saveMetadata(db, user, accountUser, { [METADATA_KEY]: [...devices, {
    id: credential.id, publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter, transports: credential.transports ?? [], status: 'approved',
  }], [PENDING_KEY]: null });
  issueAccess(res, getSecret(secret), user, credential.id);
  return { status: 200, body: { approved: true } };
}

export async function beginVerification({ res, user, db, secret, config }) {
  const accountUser = await account(db, user);
  if (!accountUser) return { status: 403, body: { error: 'DEVICE_VERIFICATION_UNAVAILABLE' } };
  const devices = registeredDevices(accountUser);
  if (!devices.length) return { status: 403, body: { error: 'DEVICE_NOT_REGISTERED' } };
  const { rpID } = deviceOrigin(config);
  const options = await generateAuthenticationOptions({
    rpID, userVerification: 'required',
    // Do not force the browser to use an internal-only transport: an already
    // approved authenticator may confirm a new browser over WebAuthn hybrid.
    allowCredentials: devices.map(item => ({ id: item.id })),
  });
  await rememberPending(db, user, accountUser, 'verify', options.challenge);
  issueChallenge(res, getSecret(secret), user, 'verify', options.challenge);
  return { status: 200, body: { options } };
}

export async function finishVerification({ req, res, user, db, secret, config, response }) {
  const challenge = challengeFor(req, getSecret(secret), user, 'verify');
  if (!challenge) return { status: 403, body: { error: 'DEVICE_CHALLENGE_REQUIRED' } };
  setCookie(res, CHALLENGE_COOKIE, '', 0);
  const accountUser = await account(db, user);
  if (!matchingPending(accountUser, 'verify', challenge)) {
    return { status: 403, body: { error: 'DEVICE_CHALLENGE_REQUIRED' } };
  }
  const devices = registeredDevices(accountUser);
  const match = devices.find(item => item.id === response?.id);
  if (!match) return { status: 403, body: { error: 'DEVICE_NOT_REGISTERED' } };
  let verification;
  try {
    const { origin, rpID } = deviceOrigin(config);
    verification = await verifyAuthenticationResponse({
      response, expectedChallenge: challenge, expectedOrigin: origin,
      expectedRPID: rpID, requireUserVerification: true,
      credential: { id: match.id, publicKey: new Uint8Array(Buffer.from(match.publicKey, 'base64url')),
        counter: match.counter, transports: match.transports },
    });
  } catch {
    return { status: 403, body: { error: 'DEVICE_PROOF_INVALID' } };
  }
  if (!verification.verified) return { status: 403, body: { error: 'DEVICE_PROOF_INVALID' } };
  if (verification.authenticationInfo.credentialDeviceType !== 'singleDevice'
      || verification.authenticationInfo.credentialBackedUp) {
    return { status: 403, body: { error: 'DEVICE_BOUND_KEY_REQUIRED' } };
  }
  await saveMetadata(db, user, accountUser, { [METADATA_KEY]: devices.map(item => item.id === match.id
    ? { ...item, counter: verification.authenticationInfo.newCounter } : item), [PENDING_KEY]: null });
  issueAccess(res, getSecret(secret), user, match.id);
  return { status: 200, body: { approved: true } };
}
