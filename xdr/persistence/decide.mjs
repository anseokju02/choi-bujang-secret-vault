// patterns.json의 복합 증거 기준을 격리 실행할 이 파일 안에 옮겼다.
// 경로·계정·T1543/T1053 태그 하나만으로 차단하지 않는다.
const PATTERNS = Object.freeze({
  unsigned: /서명 없는|서명이 없습니다|서명되지 않은/u,
  service: /서비스/u,
  scheduled: /예약 작업/u,
  startup: /시작 폴더|시작 프로그램|시작 항목/u,
  tempPath: /(?:^|[\\/])Temp[\\/]|(?:^|\/)tmp\//iu,
  startupPath: /[\\/]Start Menu[\\/]Programs[\\/]Startup[\\/]/iu,
  ambiguous: /서비스|예약 작업|시작 폴더|시작 프로그램|시작 항목|임시 폴더/u,
  approved: /서명된 채로|승인된|허가된|관리자가 승인한/u,
  unchanged: /기존.*(?:서명된 채로|정상 실행|정상 동작|평소대로|변경 없음|수업 자료 복사를 마쳤)|운영체제 업데이트.*(?:평소 시각에 그대로|변경 없음)|목록을 읽기만/u,
});

function countOf(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,6}$/u.test(value)) return Number(value);
  return null;
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description : '';
  const path = typeof alert?.data?.path === 'string' && alert.data.path.length <= 8192
    ? alert.data.path : '';
  const hasSource = typeof alert?.data?.srcip === 'string'
    && alert.data.srcip.trim() !== '';
  const count = countOf(alert?.data?.count);
  const temp = PATTERNS.tempPath.test(path);
  const service = PATTERNS.service.test(description);
  const task = PATTERNS.scheduled.test(description);
  const startup = PATTERNS.startup.test(description);
  const unsigned = PATTERNS.unsigned.test(description);
  const explicitlyApproved = PATTERNS.approved.test(description);

  const unsignedTempService = service && temp && unsigned
    && /새 서비스|서비스 등록|서비스 실행 파일이 바뀌/u.test(description);
  const remoteUnsignedService = service && unsigned && /원격 주소/u.test(description)
    && /서비스 등록/u.test(description) && count !== null && count >= 3;
  const unknownTempTask = task && temp
    && /처음 보는|임의 문자열|수업 시간 밖/u.test(description);
  const unlistedStartup = startup && PATTERNS.startupPath.test(path)
    && /평소 목록에 없는/u.test(description) && /추가됐/u.test(description);
  const pairedAutorun = task && startup && temp && /같은 임시 파일/u.test(description);
  const unlistedService = service && temp && /평소 목록에 없는/u.test(description)
    && /다시 켜도 남도록 등록/u.test(description);
  const confirmed = unsignedTempService || remoteUnsignedService || unknownTempTask
    || unlistedStartup || pairedAutorun || unlistedService;

  if (hasSource && confirmed && !explicitlyApproved) {
    const reason = unsignedTempService ? '서명 없는 서비스가 임시 위치의 실행 대상을 사용함'
      : remoteUnsignedService ? '원격 주소에서 서명 없는 서비스 등록이 반복됨'
        : unknownTempTask ? '낯선 예약 작업이 임시 위치의 실행 대상을 사용함'
          : unlistedStartup ? '기존 목록에 없는 실행 파일이 시작 폴더에 추가됨'
            : pairedAutorun ? '시작 프로그램과 예약 작업이 동일한 임시 대상을 등록함'
              : '목록 밖 서비스가 임시 대상으로 재시작 후에도 남도록 등록됨';
    return { action: 'block', confidence: pairedAutorun ? 0.95 : 0.91, reason };
  }

  if (explicitlyApproved && !unsigned) {
    return {
      action: 'record', confidence: 0.25,
      reason: '서명 또는 승인이 확인된 자동 실행 항목',
    };
  }

  if (confirmed || (!PATTERNS.unchanged.test(description)
      && PATTERNS.ambiguous.test(description))) {
    return {
      action: 'alert', confidence: confirmed ? 0.69 : 0.55,
      reason: '자동 실행 관련 변경은 보이지만 승인·등록·지속성 근거를 더 확인해야 함',
    };
  }

  return {
    action: 'record', confidence: 0.2,
    reason: '새로운 비승인 자동 실행 항목의 근거가 확인되지 않음',
  };
}
