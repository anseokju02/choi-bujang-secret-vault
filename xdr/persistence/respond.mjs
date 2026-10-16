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
    const agentName = alert?.agent?.name;
    if (typeof agentName !== 'string' || !agentName.trim()) continue;
    if (!grouped.has(agentName)) grouped.set(agentName, []);
    grouped.get(agentName).push(alert.id);
  }

  // Wazuh 모양의 agent.name은 운영 엔진이 검증한 deviceId가 아니다.
  // 실제 PC의 접속을 막았다고 표시하거나 이 후보를 src/decider.mjs에 주입하지 않는다.
  const quarantineCandidates = [...grouped].map(([agentName, evidenceAlertIds]) => ({
    proposedDecision: 'quarantine',
    status: 'pending_verified_device_attribution',
    active: false,
    agentName,
    startsAt,
    expiresAt,
    evidenceAlertIds,
  }));
  const alertsLog = decisions
    .filter(({ result }) => result.action === 'block' || result.action === 'alert')
    .map(({ alert, result }) => JSON.stringify({
      at: startsAt,
      moduleKey: 'persistence',
      alertId: alert.id,
      action: result.action,
      confidence: result.confidence,
      reason: result.reason,
    }));
  return { quarantineCandidates, alertsLog };
}

async function readOtherModuleLogs(path) {
  let contents;
  try { contents = await readFile(path, 'utf8'); }
  catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  return contents.split('\n').filter(Boolean).filter((line) => {
    try { return JSON.parse(line).moduleKey !== 'persistence'; }
    catch { return true; }
  });
}

export async function respond() {
  const fixture = JSON.parse(await readFile(join(xdrRoot, 'fixtures', 'persistence.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'persistence'
      || !Array.isArray(fixture.alerts)) throw new Error('지속성 경보 형식이 아닙니다.');

  const { quarantineCandidates, alertsLog } = planResponse(fixture.alerts);
  const logPath = join(xdrRoot, 'alerts.log');
  const otherModuleLogs = await readOtherModuleLogs(logPath);
  await writeFile(logPath, `${[...otherModuleLogs, ...alertsLog].join('\n')}\n`, 'utf8');
  await mkdir(join(projectRoot, 'artifacts'), { recursive: true });
  await writeFile(join(projectRoot, 'artifacts', 'xdr-persistence-quarantine-candidates.json'),
    `${JSON.stringify({ quarantineCandidates }, null, 2)}\n`, 'utf8');
  return { candidates: quarantineCandidates.length, alerts: alertsLog.length, activeIsolationRules: 0 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await respond()));
}
