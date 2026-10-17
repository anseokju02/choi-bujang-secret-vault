import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// 설명 원문, 목적지, 파일 이름 등은 화면에 되풀이하지 않는다.
function summarize(description) {
  if (typeof description !== 'string') return '설명 없음';
  const categories = [];
  if (/처음 보는|평소와 다른|외부 주소/u.test(description)) categories.push('목적지 정황');
  if (/대용량|큰 파일|자료실 전체|자료 200건|메모 묶음/u.test(description)) categories.push('전송 규모 정황');
  if (/반복|연속|\d+번|10분 안|짧은 시간/u.test(description)) categories.push('반복·속도 정황');
  if (/압축 파일/u.test(description)) categories.push('압축 파일 정황');
  if (/수업 시간 밖|업무 시간 밖/u.test(description)) categories.push('시간 정황');
  if (/명령 통로|쓰지 않던 포트/u.test(description)) categories.push('전송 경로 정황');
  if (/실패|전송은 아직 없|전송은 없/u.test(description)) categories.push('전송 미완료 정황');
  return categories.join(', ') || '일반 자료 활동';
}

function virtualSourceIp(value) {
  if (typeof value !== 'string' || isIP(value) !== 4) return '확인되지 않음';
  return /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/u.test(value)
    ? value : '가상 대역 외 입력';
}

function virtualAccount(value) {
  return typeof value === 'string' && /^(?:user\d{1,4}|admin\d{1,4}|svc-lab)$/u.test(value)
    ? value : '가상 형식 외 입력';
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(join(here, '..', 'fixtures', 'exfiltration.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'exfiltration'
      || !Array.isArray(fixture.alerts)) throw new Error('외부 전송 경보 형식이 아닙니다.');

  return fixture.alerts.map((alert) => ({
    id: typeof alert?.id === 'string' && /^ex-\d{2,4}$/u.test(alert.id)
      ? alert.id : '확인되지 않음',
    at: typeof alert?.timestamp === 'string' && Number.isFinite(Date.parse(alert.timestamp))
      ? new Date(alert.timestamp).toISOString() : '확인되지 않음',
    sourceIp: virtualSourceIp(alert?.data?.srcip),
    account: virtualAccount(alert?.data?.srcuser),
    ruleLevel: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: summarize(alert?.rule?.description),
  }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rows = await readAlerts();
  console.log(`경보 ${rows.length}건 / 뽑은 줄 ${rows.length}줄`);
  for (const row of rows) console.log(JSON.stringify(row));
}
