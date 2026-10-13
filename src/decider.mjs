// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  const deviceRegistered = request.deviceRegistered === true;

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: deviceRegistered ? 'allow' : 'deny',
    reasonCode: deviceRegistered ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
