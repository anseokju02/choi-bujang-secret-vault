// patterns.json의 복합 증거 기준을 이 파일의 상수와 조건으로 옮겼다.
// 격리 환경에서 import, 파일 입출력, 네트워크 호출 없이 경보 하나만 판단한다.
const PATTERNS = Object.freeze({
  novelDestination: /처음 보는 (?:목적지|주소)|목적지는 처음 봅/u,
  confirmedTransfer: /나갔|전송됐|전송이 \d+번|전송이 \d+회|올라갔|복사됐/u,
  notCompleted: /전송이 실패|전송은 아직 없|파일 전송은 없습니다/u,
  routineDestination: /수업 자료 주소|평소 목적지|승인된 목적지/u,
  repeated: /반복|연속|전송이 \d+번|전송이 \d+회/u,
  compressed: /압축 파일/u,
  offHours: /수업 시간 밖|업무 시간 밖/u,
  unusualChannel: /쓰지 않던 포트|명령 통로/u,
  fullExternalCopy: /자료실 전체.*외부 주소.*복사/u,
  suspicious: /전송|목적지|주소|압축|백업|자료.*읽힌/u,
});

function countOf(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,15}$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description.slice(0, 8192) : '';
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const bytes = countOf(alert?.data?.bytes);
  const files = countOf(alert?.data?.files);
  const count = countOf(alert?.data?.count);
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim() !== '';
  const account = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.trim() !== '';
  const destination = typeof alert?.data?.dstip === 'string' && alert.data.dstip.trim() !== '';
  const novel = PATTERNS.novelDestination.test(description);
  const sent = PATTERNS.confirmedTransfer.test(description)
    && !PATTERNS.notCompleted.test(description);
  const repeated = PATTERNS.repeated.test(description) && count !== null && count >= 5;
  const large = bytes !== null && bytes >= 50_000_000;

  const burstOfFiles = novel && files !== null && files >= 100
    && /10분 안|한 번에/u.test(description);
  const compressedToNovel = novel && PATTERNS.compressed.test(description)
    && (PATTERNS.offHours.test(description)
      || /연속|두 곳/u.test(description) && files !== null && files >= 2);
  const repeatedLargeTransfer = repeated
    && (/같은 목적지/u.test(description) || PATTERNS.unusualChannel.test(description))
    && (PATTERNS.offHours.test(description) || /대용량|큰 파일|반복/u.test(description));
  const unusualPort = /쓰지 않던 포트/u.test(description)
    && files !== null && files >= 20 && /연속 전송/u.test(description);
  const fullCopy = PATTERNS.fullExternalCopy.test(description)
    && files !== null && files >= 100;

  if (source && account && destination && level >= 9 && large && sent
      && !PATTERNS.routineDestination.test(description)
      && (burstOfFiles || compressedToNovel || repeatedLargeTransfer
        || unusualPort || fullCopy)) {
    const reason = burstOfFiles ? '처음 보는 목적지로 다수 자료가 대량 전송됨'
      : compressedToNovel ? '낯선 목적지로 압축 파일이 비정상 조건에서 대량 전송됨'
        : repeatedLargeTransfer ? '같은 목적지 또는 명령 통로로 대용량 전송이 반복됨'
          : unusualPort ? '평소 쓰지 않던 포트로 다수 파일이 연속 대량 전송됨'
            : '자료실 전체가 짧은 시간에 외부 주소로 복사됨';
    return { action: 'block', confidence: 0.92, reason };
  }

  if (level >= 5 && (PATTERNS.suspicious.test(description)
      || (Array.isArray(alert?.rule?.mitre)
        && alert.rule.mitre.some((id) => id === 'T1041' || id === 'T1048')))) {
    return {
      action: 'alert', confidence: 0.58,
      reason: '외부 전송 단서는 있으나 비정상적인 대량 유출을 확정할 증거가 부족함',
    };
  }

  return {
    action: 'record', confidence: 0.2,
    reason: '대량 외부 전송이나 낯선 목적지로의 비정상 전송 근거가 없음',
  };
}
