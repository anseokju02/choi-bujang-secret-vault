import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import {
  beginRegistration, beginVerification, deviceStatus,
  finishRegistration, finishVerification,
} from '../src/device-access.mjs';

let loginVerifier;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['GET', 'POST'].includes(req.method)) {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  if (req.method === 'POST' && req.headers.origin
      && req.headers.origin !== new URL(config.publicAppUrl).origin) {
    return res.status(403).json({ error: 'FORBIDDEN_ORIGIN' });
  }
  const url = process.env.SUPABASE_URL;
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secret) return res.status(503).json({ error: 'SERVICE_NOT_CONFIGURED' });

  let user;
  try {
    loginVerifier ??= createLoginVerifier({ config, supabaseSecretKey: secret });
    user = await loginVerifier(req.headers.authorization);
  } catch {
    return res.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  }
  if (!user) return res.status(401).json({ error: 'UNAUTHORIZED' });

  const db = createClient(url, secret, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  try {
    if (req.method === 'GET') {
      return res.status(200).json(await deviceStatus({ req, user, db, secret }));
    }
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || JSON.stringify(body).length > 32768) {
      return res.status(400).json({ error: 'INVALID_DEVICE_REQUEST' });
    }
    const args = { req, res, user, db, secret, config };
    let result;
    switch (body.action) {
      case 'register-options':
        result = await beginRegistration(args);
        break;
      case 'register-verify':
        result = await finishRegistration({ ...args, response: body.response });
        break;
      case 'verify-options':
        result = await beginVerification(args);
        break;
      case 'verify-proof':
        result = await finishVerification({ ...args, response: body.response });
        break;
      default:
        return res.status(400).json({ error: 'INVALID_DEVICE_ACTION' });
    }
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(503).json({ error: 'DEVICE_SERVICE_UNAVAILABLE' });
  }
}
