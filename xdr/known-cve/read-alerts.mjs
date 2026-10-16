import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// 요청 머리글·URL·설명 원문에는 실행 가능한 표기나 비밀값이 있을 수 있다.
function summarize(description) {
  if (typeof description !== 'string') return '설명 없음';
  const categories = [];
  if (/CVE-\d{4}-\d+/iu.test(description)) categories.push('공개 취약점 번호 언급');
  if (/원격 조회 구문|조회 구문|악용 구문/u.test(description)) categories.push('조회 구문 언급');
  if (/반복|\d+번|여러 머리글/u.test(description)) categories.push('복수 요청 언급');
  if (/없습니다|잘린 글자|완전한 구문은 아닙니다/u.test(description)) categories.push('완전한 구문 미확인');
  return categories.join(', ') || '일반 웹 활동';
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(join(here, '..', 'fixtures', 'known-cve.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'known-cve'
      || !Array.isArray(fixture.alerts)) throw new Error('공개 취약점 경보 형식이 아닙니다.');

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
