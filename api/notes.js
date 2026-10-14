
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { requireApprovedDevice } from '../src/device-access.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let loginVerifier;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['GET', 'POST'].includes(req.method)) {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(503).json({
      error: 'SERVICE_NOT_CONFIGURED'
    });
  }

  // 서버에서 로그인 토큰 검증
  let verifiedUser;

  try {
    if (!loginVerifier) {
      loginVerifier = createLoginVerifier({
        config,
        supabaseSecretKey: key
      });
    }

    verifiedUser = await loginVerifier(
      req.headers.authorization
    );
  } catch {
    return res.status(503).json({
      error: 'AUTH_UNAVAILABLE'
    });
  }

  if (!verifiedUser) {
    return res.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  const supabase = createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });

  let approved;
  try {
    approved = await requireApprovedDevice({ req, user: verifiedUser, db: supabase, secret: key });
  } catch {
    return res.status(503).json({ error: 'DEVICE_SERVICE_UNAVAILABLE' });
  }
  if (!approved) return res.status(403).json({ error: 'DEVICE_NOT_APPROVED' });

  // GET: 로그인한 사용자의 메모 목록
  if (req.method === 'GET') {
    try {
      const { data, error } = await supabase
        .from('aleph_vault_notes')
        .select('id, title, content')
        .eq('owner_id', verifiedUser.userId)
        .order('created_at', { ascending: true });

      if (error) {
        return res.status(502).json({
          error: 'NOTES_UNAVAILABLE'
        });
      }

      return res.status(200).json({
        notes: data
      });
    } catch {
      return res.status(502).json({
        error: 'NOTES_UNAVAILABLE'
      });
    }
  }

  // POST: 새로운 가상 메모 추가
  let payload;

  try {
    payload = typeof req.body === 'string'
      ? JSON.parse(req.body)
      : req.body;
  } catch {
    return res.status(400).json({
      error: 'INVALID_JSON'
    });
  }

  if (!payload || typeof payload !== 'object' ||
      Array.isArray(payload)) {
    return res.status(400).json({
      error: 'INVALID_BODY'
    });
  }

  const { id, title, body } = payload;

  if (
    typeof title !== 'string' ||
    !title.trim() ||
    title.length > 200 ||
    typeof body !== 'string' ||
    body.length > 5000 ||
    (id !== undefined &&
     (typeof id !== 'string' ||
      !UUID_PATTERN.test(id)))
  ) {
    return res.status(400).json({
      error: 'INVALID_NOTE'
    });
  }

  // 요청자가 owner_id를 지정하지 못하도록
  // 서버에서 검증된 사용자 ID만 사용
  const newNote = {
    title: title.trim(),
    content: body,
    owner_id: verifiedUser.userId
  };

  // ID가 없으면 DB에서 UUID 자동 생성
  if (id !== undefined) {
    newNote.id = id;
  }

  try {
    const { data, error } = await supabase
      .from('aleph_vault_notes')
      .insert(newNote)
      .select('id, title, content')
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({
          error: 'NOTE_CONFLICT'
        });
      }

      return res.status(502).json({
        error: 'NOTE_CREATE_FAILED'
      });
    }

    return res.status(201).json({
      id: data.id,
      title: data.title,
      body: data.content
    });
  } catch {
    return res.status(502).json({
      error: 'NOTE_CREATE_FAILED'
    });
  }
}
