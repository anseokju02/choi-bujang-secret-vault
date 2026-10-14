// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_route_policy',
]);

function knownText(value) {
  return typeof value === 'string' && value.trim() !== ''
    && value !== 'unknown' ? value : null;
}

function validEvent(event) {
  return event !== null && typeof event === 'object' && !Array.isArray(event)
    && typeof event.kind === 'string' && event.kind.length > 0
    && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0
    && Number.isInteger(event.count) && event.count >= 0;
}

// 누락된 신호를 정상값으로 채우지 않고, 가상 사건을 실제 위치 정보로 취급하지 않는다.
export function inspectAccessInputs(request) {
  const signals = request?.signals;
  const source = signals?.source === 'judge_fixture' ? 'judge_fixture'
    : signals?.source === 'none' ? 'none' : null;
  const fixture = source === 'judge_fixture';
  const events = request?.recentEvents;

  return {
    source,
    isFixture: fixture,
    region: fixture ? knownText(signals.region) : null,
    network: fixture ? knownText(signals.network) : null,
    hour: fixture && Number.isInteger(signals.hour)
      && signals.hour >= 0 && signals.hour <= 23 ? signals.hour : null,
    recentEvents: Array.isArray(events) && events.length <= 12
      && events.every(validEvent) ? events : null,
  };
}

// 엔진이 확인한 경로 모양과 실제 요청 경로가 모두 단일 자료 조회인지 확인한다.
// 로컬 7단계 가상 사건의 /notes/:id와 서버의 /api/notes/:id를 모두 지원한다.
function readableResource(request) {
  if (request?.method !== 'GET'
      || typeof request.route !== 'string'
      || typeof request.path !== 'string') return false;

  const routeMatch = /^GET \/(?:api\/)?(notes|announcements)\/:id$/u.exec(request.route);
  const pathMatch = /^\/(?:api\/)?(notes|announcements)\/([^/?#]+)$/u.exec(request.path);
  return routeMatch !== null && pathMatch !== null
    && routeMatch[1] === pathMatch[1];
}

export async function decide(request) {
  const deviceRegistered = request.deviceRegistered === true;
  const resourceAllowed = readableResource(request);
  const inputs = inspectAccessInputs(request);

  const unusualHour = inputs.isFixture && inputs.hour !== null
    && (inputs.hour < 6 || inputs.hour >= 22);
  const unfamiliarNetwork = inputs.isFixture && inputs.network === 'unusual';
  const burst = Array.isArray(inputs.recentEvents)
    && inputs.recentEvents.some((event) =>
      event.kind === 'risk_signal'
      && event.ageSeconds <= 300
      && event.count >= 10);
  const recentlyVerified = request.stepUp?.verified === true
    && Number.isInteger(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0
    && request.stepUp.authAgeSeconds <= 900;
  const shouldStepUp = deviceRegistered && resourceAllowed
    && unusualHour && unfamiliarNetwork && burst
    && !recentlyVerified;

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: !deviceRegistered || !resourceAllowed ? 'deny'
      : shouldStepUp ? 'step_up' : 'allow',
    reasonCode: !deviceRegistered ? 'device_not_registered'
      : !resourceAllowed ? 'route_not_allowed'
        : shouldStepUp ? 'step_up_required' : 'approved',
    ruleIds: !deviceRegistered ? [RULE_IDS[0]]
      : !resourceAllowed ? [RULE_IDS[0], RULE_IDS[2]]
        : shouldStepUp ? [RULE_IDS[0], RULE_IDS[1], RULE_IDS[2]]
          : [RULE_IDS[0], RULE_IDS[2]],
  };
}
