
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

let loginVerifier;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['GET', 'PUT', 'DELETE'].includes(req.method)) {
    res.setHeader('Allow', 'GET, PUT, DELETE');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(503).json({ error: 'SERVICE_NOT_CONFIGURED' });
  }

  let user;

  try {
    if (!loginVerifier) {
      loginVerifier = createLoginVerifier({
        config,
        supabaseSecretKey: key
      });
    }

    user = await loginVerifier(req.headers.authorization);
  } catch {
    return res.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  }

  if (!user) {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }

  const pathId = new URL(
    req.url, 'https://example.invalid'
  ).pathname.split('/').pop();

  const id = UUID.test(pathId ?? '')
    ? pathId
    : req.query?.id;

  if (typeof id !== 'string' || !UUID.test(id)) {
    return res.status(400).json({ error: 'INVALID_ID' });
  }

  const supabase = createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase
        .from('aleph_vault_notes')
        .select('id, title, content')
        .eq('id', id)
        .maybeSingle();

      if (error) {
        return res.status(502).json({ error: 'NOTE_READ_FAILED' });
      }

      if (!data) {
        return res.status(404).json({ error: 'NOTE_NOT_FOUND' });
      }

      return res.status(200).json({
        id: data.id,
        title: data.title,
        body: data.content
      });
    }

    if (req.method === 'PUT') {
      let payload;

      try {
        payload = typeof req.body === 'string'
          ? JSON.parse(req.body)
          : req.body;
      } catch {
        return res.status(400).json({ error: 'INVALID_JSON' });
      }

      if (!payload || typeof payload !== 'object' ||
          Array.isArray(payload) ||
          typeof payload.title !== 'string' ||
          !payload.title.trim() ||
          payload.title.length > 200 ||
          typeof payload.body !== 'string' ||
          payload.body.length > 5000) {
        return res.status(400).json({ error: 'INVALID_NOTE' });
      }

      const { data, error } = await supabase
        .from('aleph_vault_notes')
        .update({
          title: payload.title.trim(),
          content: payload.body
        })
        .eq('id', id)
        .select('id, title, content')
        .maybeSingle();

      if (error?.code === '23505') {
        return res.status(409).json({ error: 'NOTE_CONFLICT' });
      }

      if (error) {
        return res.status(502).json({ error: 'NOTE_UPDATE_FAILED' });
      }

      if (!data) {
        return res.status(404).json({ error: 'NOTE_NOT_FOUND' });
      }

      return res.status(200).json({
        id: data.id,
        title: data.title,
        body: data.content
      });
    }

    if (req.method === 'DELETE') {
      const { data, error } = await supabase
        .from('aleph_vault_notes')
        .delete()
        .eq('id', id)
        .select('id')
        .maybeSingle();

      if (error) {
        return res.status(502).json({ error: 'NOTE_DELETE_FAILED' });
      }

      if (!data) {
        return res.status(404).json({ error: 'NOTE_NOT_FOUND' });
      }

      return res.status(204).end();
    }
  } catch {
    return res.status(502).json({ error: 'NOTE_OPERATION_FAILED' });
  }
}
