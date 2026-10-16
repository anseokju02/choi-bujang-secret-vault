import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// 서비스/작업의 실행 경로와 설명 원문은 출력하지 않는다.
function summarize(description) {
  if (typeof description !== 'string') return '설명 없음';
  const categories = [];
  if (/서비스/u.test(description)) categories.push('서비스 관련');
  if (/예약 작업/u.test(description)) categories.push('예약 작업 관련');
  if (/시작 폴더|시작 프로그램|시작 항목/u.test(description)) categories.push('시작 항목 관련');
  if (/서명 없|서명이 없습니다/u.test(description)) categories.push('서명 미확인 또는 없음');
  if (/임시 폴더|임시 파일/u.test(description)) categories.push('임시 위치 언급');
  if (/기존|평소|수업/u.test(description)) categories.push('기존·수업 정황 언급');
  return categories.join(', ') || '일반 시스템 활동';
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(join(here, '..', 'fixtures', 'persistence.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'persistence'
      || !Array.isArray(fixture.alerts)) throw new Error('지속성 경보 형식이 아닙니다.');

  return fixture.alerts.map((alert) => ({
    id: alert.id,
    sourceIp: alert.data?.srcip ?? '확인되지 않음',
    account: alert.data?.srcuser ?? '확인되지 않음',
    ruleLevel: alert.rule?.level ?? null,
    description: summarize(alert.rule?.description),
  }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rows = await readAlerts();
  console.log(`경보 ${rows.length}건 / 뽑은 줄 ${rows.length}줄`);
  for (const row of rows) console.log(JSON.stringify(row));
}
