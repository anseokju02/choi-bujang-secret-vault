
import { createClient } from '@supabase/supabase-js';
import { clearDeviceCookies } from '../src/device-access.mjs';

const COOKIE = '__Host-aleph-refresh';

function makeClient() {
  return createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_PUBLISHABLE_KEY,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false
      }
    }
  );
}

function setRefreshCookie(res, token) {
  const value = encodeURIComponent(token);

  res.setHeader(
    'Set-Cookie',
    `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
  );
}

function clearRefreshCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );
}

function readRefreshCookie(req) {
  const cookies = (req.headers.cookie || '').split(';');

  const entry = cookies
    .map(item => item.trim())
    .find(item => item.startsWith(`${COOKIE}=`));

  if (!entry) return null;

  try {
    return decodeURIComponent(
      entry.slice(COOKIE.length + 1)
    );
  } catch {
    return null;
  }
}

function sendSession(res, session, user, clearDevice = false) {
  setRefreshCookie(res, session.refresh_token);
  if (clearDevice) clearDeviceCookies(res);

  return res.status(200).json({
    accessToken: session.access_token,
    expiresAt: session.expires_at,
    user: {
      email: user?.email ?? null
    }
  });
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['GET', 'POST', 'DELETE'].includes(req.method)) {
    res.setHeader('Allow', 'GET, POST, DELETE');
    return res.status(405).json({
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  // 다른 사이트에서 로그인·로그아웃 요청 방지
  if (
    ['POST', 'DELETE'].includes(req.method) &&
    req.headers.origin &&
    req.headers.origin !== `https://${req.headers.host}`
  ) {
    return res.status(403).json({
      error: 'FORBIDDEN_ORIGIN'
    });
  }

  if (
    !process.env.SUPABASE_URL ||
    !process.env.SUPABASE_PUBLISHABLE_KEY
  ) {
    return res.status(503).json({
      error: 'AUTH_NOT_CONFIGURED'
    });
  }

  try {
    const supabase = makeClient();

    // POST: 이메일·비밀번호 로그인
    if (req.method === 'POST') {
      let body;

      try {
        body = typeof req.body === 'string'
          ? JSON.parse(req.body)
          : req.body;
      } catch {
        return res.status(400).json({
          error: 'INVALID_JSON'
        });
      }

      if (
        !body ||
        typeof body.email !== 'string' ||
        typeof body.password !== 'string' ||
        !body.email.trim() ||
        body.email.length > 254 ||
        !body.password ||
        body.password.length > 1024
      ) {
        return res.status(400).json({
          error: 'INVALID_LOGIN'
        });
      }

      const { data, error } =
        await supabase.auth.signInWithPassword({
          email: body.email.trim(),
          password: body.password
        });

      if (error || !data?.session) {
        return res.status(401).json({
          error: 'INVALID_CREDENTIALS'
        });
      }

      return sendSession(
        res,
        data.session,
        data.user,
        true
      );
    }

    const refreshToken = readRefreshCookie(req);

    // GET: 서버에서 로그인 세션 갱신
    if (req.method === 'GET') {
      if (!refreshToken) {
        return res.status(401).json({
          error: 'UNAUTHORIZED'
        });
      }

      const { data, error } =
        await supabase.auth.refreshSession({
          refresh_token: refreshToken
        });

      if (error || !data?.session) {
        clearRefreshCookie(res);
        return res.status(401).json({
          error: 'UNAUTHORIZED'
        });
      }

      return sendSession(
        res,
        data.session,
        data.user
      );
    }

    // DELETE: 현재 로그인 세션 로그아웃
    if (refreshToken) {
      const { error } =
        await supabase.auth.refreshSession({
          refresh_token: refreshToken
        });

      if (!error) {
        await supabase.auth.signOut({
          scope: 'local'
        });
      }
    }

    clearRefreshCookie(res);
    clearDeviceCookies(res);
    return res.status(204).end();

  } catch {
    return res.status(503).json({
      error: 'AUTH_UNAVAILABLE'
    });
  }
}
