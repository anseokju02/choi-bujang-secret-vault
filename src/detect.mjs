// 로컬 계약에 있는 시각, 요청 종류, 가명 주체만 탐지에 사용한다.
// 브라우저가 보낸 신원이나 사건에 섞인 메모 내용·토큰은 사용하지 않는다.
export function inspectDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const inspected = [];
  for (const event of events) {
    if (event === null || typeof event !== 'object' || Array.isArray(event)
        || typeof event.at !== 'string'
        || typeof event.method !== 'string'
        || !/^[A-Z]{3,10}$/u.test(event.method)
        || typeof event.identity?.sub !== 'string'
        || event.identity.sub.trim() === '') continue;

    const at = Date.parse(event.at);
    if (!Number.isFinite(at) || new Date(at).toISOString() !== event.at) continue;
    inspected.push({ at, method: event.method, subject: event.identity.sub });
  }
  return inspected;
}

const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

// 로컬 계약에 따른 조회 폭주 제안이다. 접속 허용/거부를 직접 바꾸지 않는다.
export function detect(events) {
  const reads = inspectDetectionEvents(events)
    .filter((event) => event.method === 'GET')
    .sort((left, right) => left.at - right.at
      || left.subject.localeCompare(right.subject));
  const bySubject = new Map();

  for (const read of reads) {
    let window = bySubject.get(read.subject);
    if (!window) {
      window = { times: [], start: 0 };
      bySubject.set(read.subject, window);
    }
    window.times.push(read.at);
    while (read.at - window.times[window.start] > WINDOW_MS) {
      window.start += 1;
    }
    if (window.times.length - window.start > READ_LIMIT) {
      return {
        action: 'propose_revocation',
        reasonCode: 'burst_read',
        subject: read.subject,
      };
    }
  }

  return { action: 'observe' };
}
