import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { requireApprovedDevice } from '../../src/device-access.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

let loginVerifier;
const NOTICE_ID = 'stage8-notice-1';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) {
    return res.status(503).json({ error: 'SERVICE_NOT_CONFIGURED' });
  }

  let verifiedUser;
  try {
    if (!loginVerifier) {
      loginVerifier = createLoginVerifier({
        config,
        supabaseSecretKey: key
      });
    }
    verifiedUser = await loginVerifier(req.headers.authorization);
  } catch {
    return res.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  }
  if (!verifiedUser) {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }

  let approved;
  try {
    const db = createClient(process.env.SUPABASE_URL, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    approved = await requireApprovedDevice({ req, user: verifiedUser, db, secret: key });
  } catch {
    return res.status(503).json({ error: 'DEVICE_SERVICE_UNAVAILABLE' });
  }
  if (!approved) return res.status(403).json({ error: 'DEVICE_NOT_APPROVED' });

  const requestedId = new URL(req.url, 'https://example.invalid')
    .pathname.split('/').pop();
  if (requestedId !== NOTICE_ID) {
    return res.status(404).json({ error: 'ANNOUNCEMENT_NOT_FOUND' });
  }

  return res.status(200).json({
    id: NOTICE_ID,
    resourceId: `announcement:${NOTICE_ID}`,
    title: '강사 공지 자원 (가상)',
    description: '권한 분리 실습을 위한 자원 ID 예시입니다. 실제 공지 내용은 없습니다.'
  });
}
