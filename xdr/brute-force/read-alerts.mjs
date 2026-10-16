import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// 원문 설명에는 계정 비밀값이 섞일 수 있어, 출력에는 범주만 사용한다.
function summarize(description) {
  if (typeof description !== 'string') return '설명 없음';
  const signals = [];
  if (/로그인 실패|비밀번호 실패/u.test(description)) signals.push('인증 실패');
  if (/로그인 성공|성공했습니다|성공은 없습니다/u.test(description)) signals.push('성공 여부 언급');
  if (/여러 계정|계정 이름을 바꿔|계정 \d+개|두 계정/u.test(description)) signals.push('여러 계정');
  if (/같은 주소|한 주소|평소와 다른 주소/u.test(description)) signals.push('출발지 언급');
  if (/같은 비밀번호|한 글자씩|같은 간격|잠금 뒤/u.test(description)) signals.push('반복 시도 징후');
  return signals.join(', ') || '일반 인증 활동';
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(join(here, '..', 'fixtures', 'brute-force.json'), 'utf8'));
  if (fixture.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'brute-force'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('무차별 로그인 경보 형식이 아닙니다.');
  }
  return fixture.alerts.map((alert) => ({
    id: alert.id,
    sourceIp: alert.data?.srcip ?? '확인되지 않음',
    account: alert.data?.srcuser ?? '확인되지 않음',
    ruleLevel: alert.rule?.level ?? null,
    count: alert.data?.count ?? null,
    description: summarize(alert.rule?.description),
  }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rows = await readAlerts();
  console.log(`경보 ${rows.length}건 / 뽑은 줄 ${rows.length}줄`);
  for (const row of rows) console.log(JSON.stringify(row));
}
