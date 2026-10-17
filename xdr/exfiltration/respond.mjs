import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const xdrRoot = join(here, '..');
const projectRoot = join(xdrRoot, '..');
const CANDIDATE_LIFETIME_MS = 15 * 60 * 1000;

function virtualDestination(value) {
  return typeof value === 'string' && isIP(value) === 4
    && /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/u.test(value);
}

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
    const destinationIp = alert?.data?.dstip;
    if (!virtualDestination(destinationIp)) continue;
    if (!grouped.has(destinationIp)) grouped.set(destinationIp, []);
    grouped.get(destinationIp).push(alert.id);
  }

  // 가상 목적지 IP를 운영 ZTNA 요청의 검증된 목적지로 간주할 수 없다.
  // 요청 계약에 목적지가 없으므로 실제 거부 규칙을 추가하지 않는다.
  const denyCandidates = [...grouped].map(([destinationIp, evidenceAlertIds]) => ({
    proposedDecision: 'deny_destination',
    status: 'pending_verified_destination_attribution',
    active: false,
    destinationIp,
    startsAt,
    expiresAt,
    evidenceAlertIds,
  }));
  const alertsLog = decisions
    .filter(({ result }) => result.action === 'block' || result.action === 'alert')
    .map(({ alert, result }) => JSON.stringify({
      at: startsAt,
      moduleKey: 'exfiltration',
      alertId: alert.id,
      action: result.action,
      confidence: result.confidence,
      reason: result.reason,
    }));
  return { denyCandidates, alertsLog };
}

async function readOtherModuleLogs(path) {
  let contents;
  try { contents = await readFile(path, 'utf8'); }
  catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  return contents.split('\n').filter(Boolean).filter((line) => {
    try { return JSON.parse(line).moduleKey !== 'exfiltration'; }
    catch { return true; }
  });
}

export async function respond() {
  const fixture = JSON.parse(await readFile(join(xdrRoot, 'fixtures', 'exfiltration.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'exfiltration'
      || !Array.isArray(fixture.alerts)) throw new Error('외부 전송 경보 형식이 아닙니다.');

  const { denyCandidates, alertsLog } = planResponse(fixture.alerts);
  const logPath = join(xdrRoot, 'alerts.log');
  const otherModuleLogs = await readOtherModuleLogs(logPath);
  await writeFile(logPath, `${[...otherModuleLogs, ...alertsLog].join('\n')}\n`, 'utf8');
  await mkdir(join(projectRoot, 'artifacts'), { recursive: true });
  await writeFile(join(projectRoot, 'artifacts', 'xdr-exfiltration-deny-candidates.json'),
    `${JSON.stringify({ denyCandidates }, null, 2)}\n`, 'utf8');
  return { candidates: denyCandidates.length, alerts: alertsLog.length, activeDenyRules: 0 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await respond()));
}
