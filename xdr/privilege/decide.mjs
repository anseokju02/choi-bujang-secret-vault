// patterns.json의 복합 근거를 이 파일 안에 옮겼다. 격리 심판에서 단독 실행된다.
// T1068/T1078 태그·계정 이름·규칙 수준만으로 차단하지 않는다.
const PATTERNS = Object.freeze({
  adminGroupChange: /관리자 그룹(?:에|으로|에서| )|다시 관리자로 들어왔/u,
  adminCommand: /관리자 명령|권한 명령|관리자 그룹 추가와 명령 실행/u,
  unusualTime: /수업 시간 밖|업무처럼 보이지 않는 시각/u,
  newAddress: /처음 보는 주소|주소(?:는|가)? 처음 (?:봅|보)/u,
  unfinished: /취소됐|실패|변경은 없습니다|명령은 없습니다|관리자 그룹은 아닙니다/u,
  routine: /평소 주소|평소 예약 작업|수업용 관리 계정/u,
  privilegeHint: /관리자|권한|그룹|계정 종류/u,
});

function countOf(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,6}$/u.test(value)) return Number(value);
  return null;
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description.slice(0, 8192) : '';
  const group = typeof alert?.data?.group === 'string'
    ? alert.data.group.trim().toLowerCase() : '';
  const adminGroup = group === 'administrators';
  const hasSource = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim() !== '';
  const hasAccount = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.trim() !== '';
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const count = countOf(alert?.data?.count);
  const change = adminGroup && PATTERNS.adminGroupChange.test(description);
  const command = PATTERNS.adminCommand.test(description) && /실행|명령이/u.test(description);
  const newAddress = PATTERNS.newAddress.test(description);
  const unusualTime = PATTERNS.unusualTime.test(description);
  const unfinished = PATTERNS.unfinished.test(description);

  const remoteGroupAddition = change && /원격 주소/u.test(description)
    && /추가됐|들어가/u.test(description);
  const newAdminCommand = command
    && (/방금 관리자가 된/u.test(description)
      || (change && /곧바로|같이 있/u.test(description)));
  const unusualAdminCommand = command && unusualTime && newAddress;
  const bulkAdminAddition = change && count !== null && count >= 4
    && /같은 주소|계정.*추가됐/u.test(description);
  const newAdminSession = newAddress && /세션이 관리자 권한으로 바뀌/u.test(description);
  const offHoursGroupCommand = change && command && unusualTime;
  const borrowedPrivilegeCommand = command && /다른 계정의 권한/u.test(description);
  const rapidReadmission = change && count !== null && count >= 2
    && /빠진|제외/u.test(description) && /1분 뒤|곧바로/u.test(description)
    && /다시 관리자로|다시 관리자 그룹/u.test(description);

  if (hasSource && hasAccount && level >= 9 && !unfinished
      && !PATTERNS.routine.test(description)
      && (remoteGroupAddition || newAdminCommand || unusualAdminCommand
        || bulkAdminAddition || newAdminSession || offHoursGroupCommand
        || borrowedPrivilegeCommand || rapidReadmission)) {
    const reason = remoteGroupAddition ? '원격 주소에서 관리자 그룹 편입이 확인됨'
      : newAdminCommand ? '새 관리자 권한 취득과 명령 실행이 이어짐'
        : unusualAdminCommand ? '낯선 주소·비정상 시각의 관리자 명령 실행'
          : bulkAdminAddition ? '한 주소에서 여러 계정의 관리자 그룹 편입'
            : newAdminSession ? '낯선 주소에서 관리자 세션 전환'
              : offHoursGroupCommand ? '비정상 시각에 관리자 그룹 변경과 명령 실행'
                : borrowedPrivilegeCommand ? '다른 계정의 관리자 권한으로 명령 실행'
                  : '관리자 그룹 제외 직후 빠른 재가입';
    return { action: 'block', confidence: 0.91, reason };
  }

  if (level >= 5 && (PATTERNS.privilegeHint.test(description)
      || (Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((id) => id === 'T1068' || id === 'T1078')))) {
    return {
      action: 'alert', confidence: 0.58,
      reason: '권한 관련 활동은 있으나 비정상 관리자 권한 사용을 확정할 근거가 부족함',
    };
  }

  return {
    action: 'record', confidence: 0.2,
    reason: '새로운 관리자 권한 변경이나 비정상 권한 사용 근거가 없음',
  };
}
