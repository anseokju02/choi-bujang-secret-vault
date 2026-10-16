// patterns.json의 네 기준을 격리 실행에 맞게 이 파일 안에 옮겨 적었다.
// 경보의 MITRE 표기나 규칙 수준만으로 공격이라고 단정하지 않는다.
const PATTERNS = Object.freeze({
  blockFailures: 15,
  alertFailures: 2,
  sprayAccounts: 5,
  attackTechnique: 'T1110',
});

function failureCount(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,6}$/u.test(value)) return Number(value);
  return null;
}

function accountCount(value) {
  if (typeof value !== 'string') return 0;
  return value.split(',').map((item) => item.trim()).filter(Boolean).length;
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description : '';
  const data = alert?.data;
  const count = failureCount(data?.count);
  const hasSource = typeof data?.srcip === 'string' && data.srcip.trim() !== '';
  const tagged = Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.includes(PATTERNS.attackTechnique);
  const failed = /실패/u.test(description);
  const repeated = /(?:\d+분 안|\d+분 동안|\d+건이 (?:쌓|이어)|연속|같은 간격|한 글자씩|바꿔 가며|같은 주소|한 주소|여러 계정|서로 다른 계정|성공은 없습니다)/u.test(description);
  const spray = /같은 비밀번호/u.test(description)
    && /여러 계정|서로 다른 계정|계정 \d+개/u.test(description)
    && (accountCount(data?.accounts) >= PATTERNS.sprayAccounts
      || (count !== null && count >= PATTERNS.blockFailures));

  if (hasSource && tagged && spray) {
    return {
      action: 'block', confidence: 0.94,
      reason: '한 출발지에서 여러 계정에 동일한 비밀번호를 반복 시도한 근거',
    };
  }
  if (hasSource && tagged && failed && repeated
      && count !== null && count >= PATTERNS.blockFailures) {
    return {
      action: 'block', confidence: count >= 40 ? 0.95 : 0.88,
      reason: `반복 정황이 있는 인증 실패 ${count}건`,
    };
  }
  if (hasSource && failed && count !== null && count >= PATTERNS.alertFailures) {
    return {
      action: 'alert', confidence: 0.62,
      reason: `인증 실패 ${count}건의 추가 확인 필요`,
    };
  }
  if (hasSource && (failed || repeated) && tagged) {
    return {
      action: 'alert', confidence: 0.53,
      reason: '시도 정황은 있지만 차단할 횟수·반복 근거가 부족함',
    };
  }
  return {
    action: 'record', confidence: 0.2,
    reason: '반복 인증 공격의 근거가 확인되지 않음',
  };
}
