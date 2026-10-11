
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let loginVerifier;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
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

  // 로그인 토큰 검사
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

  // 토큰이 없거나 유효하지 않으면 거부
  if (!verifiedUser) {
    return res.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  // 인증에 성공한 요청만 DB 조회
  try {
    const supabase = createClient(url, key, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });

    const { data, error } = await supabase
      .from('aleph_vault_notes')
      .select('title, content')
      .order('id', { ascending: true })
      .limit(4);

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
