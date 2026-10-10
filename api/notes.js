
import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(503).json({ error: 'SERVICE_NOT_CONFIGURED' });
  }

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
      return res.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }

    return res.status(200).json({ notes: data });
  } catch {
    return res.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
