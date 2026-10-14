import { createHash, timingSafeEqual } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/u;

export function noteDigest({ id, ownerId, title, body }) {
  return createHash('sha256').update(JSON.stringify([id, ownerId, title, body])).digest('hex');
}

function sameDigest(left, right) {
  return typeof left === 'string' && typeof right === 'string'
    && DIGEST.test(left) && DIGEST.test(right)
    && timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

// The snapshot and its previously verified digest live only in server settings.
// A request cannot supply the memo content or select another recovery target.
export function verifiedNoteBackup(backupJson, expectedDigest) {
  if (typeof backupJson !== 'string' || backupJson.length > 10000
      || !DIGEST.test(expectedDigest ?? '')) return null;
  let backup;
  try { backup = JSON.parse(backupJson); } catch { return null; }
  if (backup === null || typeof backup !== 'object' || Array.isArray(backup)
      || Object.keys(backup).sort().join(',') !== 'body,id,ownerId,title'
      || !UUID.test(backup.id) || !UUID.test(backup.ownerId)
      || typeof backup.title !== 'string' || !backup.title.trim()
      || backup.title.length > 200 || typeof backup.body !== 'string'
      || backup.body.length > 5000
      || !sameDigest(noteDigest(backup), expectedDigest)) return null;
  return Object.freeze(backup);
}

// Return only status and metadata. Never return a backup body or user token.
export async function restoreOneNote({ backup, payload, user, db }) {
  if (!backup) return { status: 503, body: { error: 'VERIFIED_BACKUP_UNAVAILABLE' } };
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)
      || Object.keys(payload).sort().join(',') !== 'contentSha256,id,ownerId'
      || payload.id !== backup.id || payload.ownerId !== backup.ownerId
      || !sameDigest(payload.contentSha256, noteDigest(backup))) {
    return { status: 400, body: { error: 'BACKUP_MISMATCH' } };
  }
  if (!user || user.userId !== backup.ownerId
      || (user.kind === 'judge' && user.identity !== 'b')
      || !['judge', 'student'].includes(user.kind)) {
    return { status: 403, body: { error: 'NOT_BACKUP_OWNER' } };
  }

  try {
    const { data: existing, error: readError } = await db
      .from('aleph_vault_notes')
      .select('id, owner_id, title, content')
      .eq('id', backup.id)
      .maybeSingle();
    if (readError) return { status: 502, body: { error: 'RESTORE_READ_FAILED' } };
    if (existing && existing.owner_id !== backup.ownerId) {
      return { status: 409, body: { error: 'OWNER_CONFLICT' } };
    }
    if (existing && existing.title === backup.title && existing.content === backup.body) {
      return { status: 200, body: { restored: false } };
    }

    const result = existing
      ? await db.from('aleph_vault_notes')
        .update({ title: backup.title, content: backup.body })
        .eq('id', backup.id).eq('owner_id', backup.ownerId)
        .select('id').maybeSingle()
      : await db.from('aleph_vault_notes')
        .insert({ id: backup.id, owner_id: backup.ownerId,
          title: backup.title, content: backup.body })
        .select('id').maybeSingle();
    if (result.error || result.data?.id !== backup.id) {
      return { status: 502, body: { error: 'RESTORE_WRITE_FAILED' } };
    }
    return { status: 200, body: { restored: true } };
  } catch {
    return { status: 502, body: { error: 'RESTORE_UNAVAILABLE' } };
  }
}
