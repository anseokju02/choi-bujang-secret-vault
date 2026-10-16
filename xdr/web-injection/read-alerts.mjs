import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// 설명이나 URL 원문에는 비밀처럼 보이는 값이 섞일 수 있으므로 범주만 표시한다.
function summarize(description) {
  if (typeof description !== 'string') return '설명 없음';
  const categories = [];
  if (/SQL\s*구문|SQL\s*표식|데이터베이스 조회를 이어 붙/u.test(description)) categories.push('SQL 구문 징후');
  if (/스크립트 삽입|스크립트 표식/u.test(description)) categories.push('스크립트 삽입 징후');
  if (/경로.*(?:거슬러 올라가|이탈)/u.test(description)) categories.push('경로 이탈 징후');
  if (/명령 구분자/u.test(description)) categories.push('명령 구분자 징후');
  if (/반복|연속|\d+번/u.test(description)) categories.push('반복 언급');
  if (/한 번|1건|반복되지 않았/u.test(description)) categories.push('단발 언급');
  return categories.join(', ') || '웹 요청 활동';
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(join(here, '..', 'fixtures', 'web-injection.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) throw new Error('웹 주입 경보 형식이 아닙니다.');

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
