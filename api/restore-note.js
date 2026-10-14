import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { restoreOneNote, verifiedNoteBackup } from '../src/restore-note.mjs';
import { requireApprovedDevice } from '../src/device-access.mjs';

let loginVerifier;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  if (req.headers.origin && req.headers.origin !== `https://${req.headers.host}`) {
    return res.status(403).json({ error: 'FORBIDDEN_ORIGIN' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return res.status(503).json({ error: 'SERVICE_NOT_CONFIGURED' });

  let user;
  try {
    loginVerifier ??= createLoginVerifier({ config, supabaseSecretKey: key });
    user = await loginVerifier(req.headers.authorization);
  } catch {
    return res.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  }
  if (!user) return res.status(401).json({ error: 'UNAUTHORIZED' });

  const db = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  let approved;
  try {
    approved = await requireApprovedDevice({ req, user, db, secret: key });
  } catch {
    return res.status(503).json({ error: 'DEVICE_SERVICE_UNAVAILABLE' });
  }
  if (!approved) return res.status(403).json({ error: 'DEVICE_NOT_APPROVED' });

  const backup = verifiedNoteBackup(
    process.env.ALEPH_RESTORE_BACKUP_JSON,
    process.env.ALEPH_RESTORE_EXPECTED_SHA256,
  );
  let payload;
  try { payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
  catch { return res.status(400).json({ error: 'INVALID_JSON' }); }

  const result = await restoreOneNote({ backup, payload, user, db: backup ? db : null });
  return res.status(result.status).json(result.body);
}
