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
    const account = alert?.data?.srcuser;
    const sourceIp = alert?.data?.srcip;
    if (typeof account !== 'string' || !account.trim()
        || typeof sourceIp !== 'string' || !sourceIp.trim()) continue;
    const key = `${account}\u0000${sourceIp}`;
    if (!grouped.has(key)) grouped.set(key, { account, sourceIp, evidenceAlertIds: [] });
    grouped.get(key).evidenceAlertIds.push(alert.id);
  }

  // 가상 경보의 계정·IP는 엔진에서 확인한 subjectId/deviceId가 아니다.
  // 상관 계약이 없으므로 실제 거부 정책을 만들거나 src/decider.mjs에 주입하지 않는다.
  const denyCandidates = [...grouped.values()].map(({ account, sourceIp, evidenceAlertIds }) => ({
    proposedDecision: 'deny',
    status: 'pending_verified_attribution',
    active: false,
    sourceAccount: account,
    sourceIp,
    startsAt,
    expiresAt,
    evidenceAlertIds,
  }));
  const alertsLog = decisions
    .filter(({ result }) => result.action === 'block' || result.action === 'alert')
    .map(({ alert, result }) => JSON.stringify({
      at: startsAt,
      moduleKey: 'privilege',
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
    try { return JSON.parse(line).moduleKey !== 'privilege'; }
    catch { return true; }
  });
}

export async function respond() {
  const fixture = JSON.parse(await readFile(join(xdrRoot, 'fixtures', 'privilege.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) throw new Error('권한 경보 형식이 아닙니다.');

  const { denyCandidates, alertsLog } = planResponse(fixture.alerts);
  const logPath = join(xdrRoot, 'alerts.log');
  const otherModuleLogs = await readOtherModuleLogs(logPath);
  await writeFile(logPath, `${[...otherModuleLogs, ...alertsLog].join('\n')}\n`, 'utf8');
  await mkdir(join(projectRoot, 'artifacts'), { recursive: true });
  await writeFile(join(projectRoot, 'artifacts', 'xdr-privilege-deny-candidates.json'),
    `${JSON.stringify({ denyCandidates }, null, 2)}\n`, 'utf8');
  return { candidates: denyCandidates.length, alerts: alertsLog.length, activeDenyRules: 0 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await respond()));
}
