import assert from 'node:assert/strict';
import test from 'node:test';
import { noteDigest, restoreOneNote, verifiedNoteBackup } from '../src/restore-note.mjs';

const note = {
  id: '00000000-0000-4000-8000-000000000010',
  ownerId: '00000000-0000-4000-8000-000000000020',
  title: '가상 B 메모',
  body: '공개 불가능한 실제 메모가 아닌 시험 문장',
};
const digest = noteDigest(note);
const backup = verifiedNoteBackup(JSON.stringify(note), digest);
const payload = { id: note.id, ownerId: note.ownerId, contentSha256: digest };
const userB = { kind: 'student', userId: note.ownerId };

function fakeDb(existing) {
  const calls = [];
  let operation = 'read';
  const db = {
    from(table) { calls.push(['from', table]); return this; },
    select(columns) { calls.push(['select', columns]); return this; },
    eq(field, value) { calls.push(['eq', field, value]); return this; },
    update(values) { operation = 'update'; calls.push(['update', values]); return this; },
    insert(values) { operation = 'insert'; calls.push(['insert', values]); return this; },
    async maybeSingle() {
      return { data: operation === 'read' ? existing : { id: note.id }, error: null };
    },
  };
  return { db, calls };
}

test('검증되지 않은 사본 또는 해시 불일치는 DB 접속 없이 중단', async () => {
  assert.equal(verifiedNoteBackup(JSON.stringify(note), 'a'.repeat(64)), null);
  const { db, calls } = fakeDb(null);
  assert.equal((await restoreOneNote({ backup: null, payload, user: userB, db })).status, 503);
  assert.equal((await restoreOneNote({ backup,
    payload: { ...payload, contentSha256: 7 }, user: userB, db })).status, 400);
  assert.equal(calls.length, 0);
});

test('A 또는 다른 ID는 지정된 B 메모를 복원할 수 없음', async () => {
  const { db, calls } = fakeDb(null);
  assert.equal((await restoreOneNote({ backup, payload,
    user: { kind: 'student', userId: '00000000-0000-4000-8000-000000000030' }, db })).status, 403);
  assert.equal((await restoreOneNote({ backup,
    payload: { ...payload, id: '00000000-0000-4000-8000-000000000011' },
    user: userB, db })).status, 400);
  assert.equal(calls.length, 0);
});

test('B의 변조된 한 건만 정확한 내용으로 수정', async () => {
  const { db, calls } = fakeDb({ id: note.id, owner_id: note.ownerId,
    title: '바뀐 제목', content: '바뀐 내용' });
  assert.deepEqual(await restoreOneNote({ backup, payload, user: userB, db }),
    { status: 200, body: { restored: true } });
  assert.equal(calls.filter(([method]) => method === 'update').length, 1);
  assert.deepEqual(calls.filter(([method]) => method === 'update')[0][1],
    { title: note.title, content: note.body });
  assert.ok(calls.some((call) => call[0] === 'eq' && call[1] === 'id' && call[2] === note.id));
  assert.ok(calls.some((call) => call[0] === 'eq'
    && call[1] === 'owner_id' && call[2] === note.ownerId));
});

test('삭제된 B 메모 한 건만 삽입, 정상 메모는 수정하지 않음', async () => {
  const absent = fakeDb(null);
  assert.equal((await restoreOneNote({ backup, payload, user: userB, db: absent.db })).status, 200);
  assert.equal(absent.calls.filter(([method]) => method === 'insert').length, 1);
  const alreadySafe = fakeDb({ id: note.id, owner_id: note.ownerId,
    title: note.title, content: note.body });
  assert.deepEqual(await restoreOneNote({ backup, payload, user: userB, db: alreadySafe.db }),
    { status: 200, body: { restored: false } });
  assert.equal(alreadySafe.calls.filter(([method]) => ['update', 'insert'].includes(method)).length, 0);
});

test('동일 ID가 다른 소유자에게 있으면 덮어쓰지 않음', async () => {
  const { db, calls } = fakeDb({ id: note.id,
    owner_id: '00000000-0000-4000-8000-000000000030' });
  assert.equal((await restoreOneNote({ backup, payload, user: userB, db })).status, 409);
  assert.equal(calls.filter(([method]) => ['update', 'insert'].includes(method)).length, 0);
});
