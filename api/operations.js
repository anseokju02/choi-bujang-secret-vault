import config from '../aleph.config.json' with { type: 'json' };
import { RULE_IDS } from '../src/decider.mjs';

// 공개 화면에는 코드와 배포의 출처만 보낸다. 실제 심판 판정이나
// 사건/회수/복구 기록을 수집하지 않은 상태는 null로 남긴다.
export function operationsSnapshot(commit = process.env.VERCEL_GIT_COMMIT_SHA) {
  return {
    schema: 'aleph.operations.v1',
    observedAt: new Date().toISOString(),
    source: 'student_project_code',
    engine: 'ALEPH SDP 엔진(제공)',
    step: config.step,
    deploymentCommit: /^[0-9a-f]{40}$/iu.test(commit ?? '') ? commit : null,
    policy: {
      ruleIds: [...RULE_IDS],
      lastEngineDecision: null,
    },
    detection: {
      latestEngineEvent: null,
      lastEngineResult: null,
    },
    revocation: {
      lastEngineAction: null,
    },
    recovery: {
      route: config.restoreRoute,
      backupVersion: null,
      lastExecutedVersion: null,
      lastExecutedAt: null,
    },
  };
}

export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  return res.status(200).json(operationsSnapshot());
}
