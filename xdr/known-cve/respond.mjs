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

  // 경보 IP와 ZTNA 판정 요청의 신뢰된 subjectId/deviceId를 연결하는 계약이 없다.
  // 실제 거부 규칙을 추가하지 않고, 근거와 만료 시각이 있는 비활성 후보만 남긴다.
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
      moduleKey: 'known-cve',
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
    try { return JSON.parse(line).moduleKey !== 'known-cve'; }
    catch { return true; }
  });
}

export async function respond() {
  const fixture = JSON.parse(await readFile(join(xdrRoot, 'fixtures', 'known-cve.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'known-cve'
      || !Array.isArray(fixture.alerts)) throw new Error('공개 취약점 경보 형식이 아닙니다.');

  const { denyCandidates, alertsLog } = planResponse(fixture.alerts);
  const logPath = join(xdrRoot, 'alerts.log');
  const otherModuleLogs = await readOtherModuleLogs(logPath);
  await writeFile(logPath, `${[...otherModuleLogs, ...alertsLog].join('\n')}\n`, 'utf8');
  await mkdir(join(projectRoot, 'artifacts'), { recursive: true });
  await writeFile(join(projectRoot, 'artifacts', 'xdr-known-cve-deny-candidates.json'),
    `${JSON.stringify({ denyCandidates }, null, 2)}\n`, 'utf8');
  return { candidates: denyCandidates.length, alerts: alertsLog.length, activeDenyRules: 0 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await respond()));
}
