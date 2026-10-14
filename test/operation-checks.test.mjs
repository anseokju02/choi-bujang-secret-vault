import assert from 'node:assert/strict';
import { test } from 'node:test';
import { operationsSnapshot } from '../api/operations.js';
import { plannedChecks, runOperationChecks } from '../public/operation-checks.js';

test('운영 기록이 없으면 성공이나 0건을 꾸며 내지 않는다', () => {
  const snapshot = operationsSnapshot('a'.repeat(40));
  assert.equal(snapshot.deploymentCommit, 'a'.repeat(40));
  assert.equal(snapshot.policy.lastEngineDecision, null);
  assert.equal(snapshot.detection.latestEngineEvent, null);
  assert.equal(snapshot.revocation.lastEngineAction, null);
  assert.equal(snapshot.recovery.lastExecutedVersion, null);
  assert.ok(snapshot.policy.ruleIds.includes('device_registered'));
});

test('실측 전 41종 심판 시험과 보호된 정상 요청은 미실행이다', () => {
  const rows = plannedChecks();
  assert.equal(rows.find(row => row.name.includes('41종')).outcome, '미실행');
  assert.equal(rows.find(row => row.name.includes('본인 메모 목록 허용')).source, 'not_executed');
  assert.equal(rows.find(row => row.name.includes('복구')).checkId, null);
});

test('실제 응답 상태가 기대와 다르면 통과로 표시하지 않고 토큰도 기록하지 않는다', async () => {
  const responseStatus = url => url.pathname === '/api/notes' ? 200 : 200;
  const rows = await runOperationChecks({ baseUrl: 'https://example.vercel.app',
    token: 'private-test-token', approved: true,
    fetcher: async (url, options) => {
      assert.ok(options.headers['X-Check-Id']);
      return { status: responseStatus(url), json: async () => ({ approved: true }) };
    },
    makeId: () => 'test-request-id', now: () => '2026-10-14T00:00:00.000Z' });
  const anonymous = rows.find(row => row.name === '비로그인 메모 목록 거부');
  const protectedRead = rows.find(row => row.name === '등록 기기의 본인 메모 목록 허용');
  assert.equal(anonymous.outcome, '확인 필요');
  assert.equal(protectedRead.outcome, '기대와 일치');
  assert.equal(rows.find(row => row.name.includes('41종')).source, 'not_executed');
  assert.equal(JSON.stringify(rows).includes('private-test-token'), false);
});

test('HTTP가 실패하면 응답 없음으로 남기고 실행하지 않은 사건은 보존한다', async () => {
  const rows = await runOperationChecks({ baseUrl: 'https://example.vercel.app',
    fetcher: async () => { throw new Error('network down'); },
    makeId: () => 'test-request-id', now: () => '2026-10-14T00:00:00.000Z' });
  assert.equal(rows[0].actual, '응답 없음');
  assert.equal(rows[0].outcome, '확인 필요');
  assert.equal(rows.find(row => row.name.includes('41종')).outcome, '미실행');
});
