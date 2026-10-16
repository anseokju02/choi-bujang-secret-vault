import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// 설명 원문에는 계정·명령 등이 들어올 수 있으므로 고정된 범주만 출력한다.
function summarize(description) {
  if (typeof description !== 'string') return '설명 없음';
  const categories = [];
  if (/관리자 그룹|다시 관리자로/u.test(description)) categories.push('관리자 그룹 변경');
  if (/관리자 명령|권한 명령|관리자 그룹 추가와 명령 실행/u.test(description)) categories.push('권한 명령');
  if (/세션이 관리자 권한으로 바뀌|권한 상승/u.test(description)) categories.push('권한 상승');
  if (/처음 보는 주소|주소(?:는|가)? 처음 (?:봅|보)|원격 주소/u.test(description)) categories.push('접속 주소 정황');
  if (/수업 시간 밖|업무처럼 보이지 않는 시각/u.test(description)) categories.push('시간 정황');
  if (/취소|실패|없습니다|아닙니다/u.test(description)) categories.push('실행·변경 미확인');
  return categories.join(', ') || '일반 계정 활동';
}

function virtualSourceIp(value) {
  if (typeof value !== 'string' || isIP(value) !== 4) return '확인되지 않음';
  if (/^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/u.test(value)) return value;
  return '가상 대역 외 입력';
}

function virtualAccount(value) {
  return typeof value === 'string' && /^(?:user\d{1,4}|admin\d{1,4}|svc-lab)$/u.test(value)
    ? value : '가상 형식 외 입력';
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(join(here, '..', 'fixtures', 'privilege.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) throw new Error('권한 경보 형식이 아닙니다.');

  return fixture.alerts.map((alert) => ({
    id: alert.id,
    sourceIp: virtualSourceIp(alert.data?.srcip),
    account: virtualAccount(alert.data?.srcuser),
    ruleLevel: Number.isInteger(alert.rule?.level) ? alert.rule.level : null,
    description: summarize(alert.rule?.description),
  }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rows = await readAlerts();
  console.log(`경보 ${rows.length}건 / 뽑은 줄 ${rows.length}줄`);
  for (const row of rows) console.log(JSON.stringify(row));
}
