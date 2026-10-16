import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const xdrRoot = join(here, '..');
const projectRoot = join(xdrRoot, '..');
const CANDIDATE_LIFETIME_MS = 15 * 60 * 1000;

export function planResponse(alerts, now = new Date()) {
  if (!Array.isArray(alerts) || !(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError('경보와 현재 시각을 확인할 수 없습니다.');
  }
  const startsAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + CANDIDATE_LIFETIME_MS).toISOString();
  const decisions = alerts.map((alert) => ({ alert, result: decide(alert) }));
  const grouped = new Map();

  for (const { alert, result } of decisions) {
    if (result.action !== 'block') continue;
    const sourceIp = alert?.data?.srcip;
    if (typeof sourceIp !== 'string' || !sourceIp.trim()) continue;
    if (!grouped.has(sourceIp)) grouped.set(sourceIp, []);
    grouped.get(sourceIp).push(alert.id);
  }

  // 출발지 IP만으로 ZTNA의 검증된 subjectId/deviceId를 알 수 없다.
  // 이 규칙들은 실제 판정기에 주입되지 않는 후보이며, 신뢰 가능한 상관 확인이 필요하다.
  const denyCandidates = [...grouped].map(([sourceIp, evidenceAlertIds]) => ({
    proposedDecision: 'deny',
    status: 'pending_verified_attribution',
    active: false,
    sourceIp,
    startsAt,
    expiresAt,
    evidenceAlertIds,
  }));
  const alertsLog = decisions
    .filter(({ result }) => result.action === 'block' || result.action === 'alert')
    .map(({ alert, result }) => JSON.stringify({
      at: startsAt,
      moduleKey: 'brute-force',
      alertId: alert.id,
      action: result.action,
      confidence: result.confidence,
      reason: result.reason,
    }));
  return { denyCandidates, alertsLog };
}

export async function respond() {
  const fixture = JSON.parse(await readFile(join(xdrRoot, 'fixtures', 'brute-force.json'), 'utf8'));
  if (fixture.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'brute-force'
      || !Array.isArray(fixture.alerts)) throw new Error('경보 묶음 형식이 아닙니다.');

  const { denyCandidates, alertsLog } = planResponse(fixture.alerts);
  await writeFile(join(xdrRoot, 'alerts.log'), `${alertsLog.join('\n')}\n`, 'utf8');
  await mkdir(join(projectRoot, 'artifacts'), { recursive: true });
  await writeFile(join(projectRoot, 'artifacts', 'xdr-brute-force-deny-candidates.json'),
    `${JSON.stringify({ denyCandidates }, null, 2)}\n`, 'utf8');
  return { candidates: denyCandidates.length, alerts: alertsLog.length, activeDenyRules: 0 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await respond()));
}
