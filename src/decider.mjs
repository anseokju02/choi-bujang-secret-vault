// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

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

// 입력의 출처와 누락 여부만 구분한다. 판정 규칙은 다음 제작에서 사용한다.
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

export async function decide(request) {
  const deviceRegistered = request.deviceRegistered === true;
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
  const shouldStepUp = deviceRegistered
    && unusualHour && unfamiliarNetwork && burst
    && !recentlyVerified;

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: !deviceRegistered ? 'deny' : shouldStepUp ? 'step_up' : 'allow',
    reasonCode: !deviceRegistered ? 'device_not_registered'
      : shouldStepUp ? 'step_up_required' : 'approved',
    ruleIds: shouldStepUp ? [RULE_IDS[0], RULE_IDS[1]] : [RULE_IDS[0]],
  };
}
