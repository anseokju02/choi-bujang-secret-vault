// HTTP 상태만 기록한다. 토큰, 쿠키, 자료 본문은 결과에 넣지 않는다.
const HTTP_CHECKS = [
  { step: '1', name: '자료실 첫 화면', method: 'GET', path: '/', expectedStatus: 200 },
  { step: '2', name: '정적 자료 제거', method: 'GET', path: '/data.json', expectedStatus: 404 },
  { step: '3', name: '비로그인 메모 목록 거부', method: 'GET', path: '/api/notes', expectedStatus: 401 },
  { step: '3', name: '잘못된 로그인 토큰 거부', method: 'GET', path: '/api/notes', expectedStatus: 401, invalidToken: true },
  { step: '4', name: '비로그인 개별 메모 거부', method: 'GET', path: '/api/notes/00000000-0000-4000-8000-000000000000', expectedStatus: 401 },
  { step: '8', name: '비로그인 공지 거부', method: 'GET', path: '/api/announcements/stage8-notice-1', expectedStatus: 401 },
  { step: '8', name: '공지 쓰기 거부', method: 'POST', path: '/api/announcements/stage8-notice-1', expectedStatus: 405 },
  { step: '8', name: '알 수 없는 강사 경로 거부', method: 'GET', path: '/api/teacher/stage8-test', expectedStatus: 404 },
  { step: '10', name: '비로그인 복구 거부', method: 'POST', path: '/api/restore-note', expectedStatus: 401, body: '{}' },
  { step: '10', name: '복구 GET 거부', method: 'GET', path: '/api/restore-note', expectedStatus: 405 },
  { step: '11', name: '설치 manifest', method: 'GET', path: '/manifest.webmanifest', expectedStatus: 200 },
  { step: '11', name: '공개 오프라인 안내', method: 'GET', path: '/offline.html', expectedStatus: 200 },
  { step: '11', name: '비로그인 기기 상태 거부', method: 'GET', path: '/api/device', expectedStatus: 401 },
  { step: '11', name: '비로그인 기기 등록 거부', method: 'POST', path: '/api/device', expectedStatus: 401, body: '{"action":"register-options"}' },
  { step: '12', name: '작전실 요약 API', method: 'GET', path: '/api/operations', expectedStatus: 200 },
];

const AUTH_CHECKS = [
  { step: '3·4·11', name: '등록 기기의 본인 메모 목록 허용', method: 'GET', path: '/api/notes', expectedStatus: 200 },
  { step: '8·11', name: '등록 기기의 강사 공지 읽기 허용', method: 'GET', path: '/api/announcements/stage8-notice-1', expectedStatus: 200 },
  { step: '11', name: '기기 승인 상태 확인', method: 'GET', path: '/api/device', expectedStatus: 200, approved: true },
];

const UNAPPROVED_CHECK = { step: '11', name: '미승인 기기의 메모 요청 거부',
  method: 'GET', path: '/api/notes', expectedStatus: 403 };

const MANUAL_CHECKS = [
  { step: '4', name: 'A/B 교차 소유권 조회·변경 거부', expected: '다른 소유자의 자료 거부' },
  { step: '5', name: '원본 DB API 직접 요청 거부', expected: '직접 읽기 거부' },
  { step: '6', name: '교육 엔진의 실제 기기 등록 판정', expected: '등록 허용·미등록 거부' },
  { step: '7', name: '실제 이상 접속 재인증', expected: '추가 확인·정상 허용' },
  { step: '9', name: '운영 사건 전달과 접속 회수', expected: '폭주 탐지·회수 집행' },
  { step: '10', name: '검증된 B 메모 복구', expected: '사본 검증 후 복구' },
  { step: '11', name: '실제 기기 등록과 재접속', expected: '등록·재확인 후 허용' },
  { step: '12', name: '운영 심판의 41종 공격', expected: '운영 심판의 실행 기록' },
];

function pending(check) {
  return { step: check.step, name: check.name, request: check.method
      ? `${check.method} ${check.path}` : '별도 환경 필요',
    expected: check.expected ?? `HTTP ${check.expectedStatus}${check.approved ? ' + approved=true' : ''}`,
    actual: null, outcome: '미실행', checkId: null, checkedAt: null, source: 'not_executed' };
}

export function plannedChecks() {
  return [...HTTP_CHECKS, ...AUTH_CHECKS, UNAPPROVED_CHECK, ...MANUAL_CHECKS].map(pending);
}

export async function runOperationChecks({ baseUrl, token = null, approved = false,
  fetcher = fetch, makeId = () => crypto.randomUUID(), now = () => new Date().toISOString() }) {
  const base = new URL(baseUrl);
  if (base.protocol !== 'https:' && base.hostname !== 'localhost') {
    throw new Error('HTTPS 자료실 주소가 필요합니다.');
  }
  const checks = [...HTTP_CHECKS, ...(token && approved ? AUTH_CHECKS : []),
    ...(token && !approved ? [UNAPPROVED_CHECK] : [])];
  const completed = new Map();
  for (const check of checks) {
    const id = makeId();
    const headers = { 'X-Check-Id': id };
    if (check.invalidToken) headers.Authorization = 'Bearer invalid.token.value';
    if (token && (AUTH_CHECKS.includes(check) || check === UNAPPROVED_CHECK)) {
      headers.Authorization = `Bearer ${token}`;
    }
    if (check.body !== undefined) headers['Content-Type'] = 'application/json';
    const row = { ...pending(check), checkId: id, checkedAt: null,
      source: 'actual_http_response' };
    try {
      const response = await fetcher(new URL(check.path, base), {
        method: check.method, headers, credentials: headers.Authorization
          && !check.invalidToken ? 'same-origin' : 'omit',
        cache: 'no-store', redirect: 'error', body: check.body,
        signal: AbortSignal.timeout(10000),
      });
      row.actual = `HTTP ${response.status}`;
      let valid = response.status === check.expectedStatus;
      if (valid && check.approved) {
        const data = await response.json();
        valid = data?.approved === true;
        row.actual += ` + approved=${data?.approved === true}`;
      }
      row.outcome = valid ? '기대와 일치' : '확인 필요';
    } catch {
      row.actual = '응답 없음';
      row.outcome = '확인 필요';
    }
    row.checkedAt = now();
    completed.set(check, row);
  }
  return [...HTTP_CHECKS, ...AUTH_CHECKS, UNAPPROVED_CHECK, ...MANUAL_CHECKS]
    .map(check => completed.get(check) ?? pending(check));
}
