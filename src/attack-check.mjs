
export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) {
    throw new Error('지원하지 않는 점검 단계입니다.');
  }

  const app = new URL(config.publicAppUrl);

  if (
    app.protocol !== 'https:' ||
    app.hostname.endsWith('.example')
  ) {
    throw new Error('실제 HTTPS 배포 주소를 확인하세요.');
  }

  async function check(path, attackId, options = {}) {
    const url = new URL(path, app);
    // 각 공개 요청과 제출 묶음의 attackId를 같은 값으로 연결한다.
    url.searchParams.set('attackId', attackId);
    return fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      ...options,
      headers: { ...options.headers, 'X-Attack-Id': attackId, 'X-Check-Id': attackId },
    });
  }

  // 정적 메모 노출 확인
  const staticResponse = await check('/data.json', config.step === 1
    ? 'anonymous_note_read' : 'static_note_exposure');

  let exposed = false;

  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      exposed = Array.isArray(data.notes) &&
        data.notes.length > 0;
    } catch {
      exposed = false;
    }
  }

  // 1단계 점검 유지
  if (config.step === 1) {
    return [{
      attackId: 'anonymous_note_read',
      expected: '비로그인 가상 메모 공개 확인',
      observed: exposed
        ? '공개 메모 확인 표시가 보임'
        : `공개 메모 확인 표시가 보이지 않음 (HTTP ${staticResponse.status})`
    }];
  }

  // 비로그인 목록 요청
  const apiResponse = await check('/api/notes', 'anonymous_api_read');

  // 2단계 점검 유지
  if (config.step === 2) {
    let noteCount = null;

    if (apiResponse.ok) {
      try {
        const data = await apiResponse.json();
        if (Array.isArray(data.notes)) {
          noteCount = data.notes.length;
        }
      } catch {
        noteCount = null;
      }
    }

    return [
      {
        attackId: 'static_note_exposure',
        expected: '정적 메모 노출 없음',
        observed: exposed
          ? '정적 메모 노출 확인'
          : `정적 메모 노출 없음 (HTTP ${staticResponse.status})`
      },
      {
        attackId: 'anonymous_api_read',
        expected: '2단계 공개 API 메모 조회 확인',
        observed: noteCount === 4
          ? '비로그인 메모 4건 조회 확인'
          : `조회 결과 확인 필요 (HTTP ${apiResponse.status})`
      }
    ];
  }

  // 3단계: 잘못된 토큰 검사
  const invalidTokenResponse = await check('/api/notes', 'invalid_login_token', {
    headers: {
      Authorization: 'Bearer invalid.token.value'
    }
  });

  // 3단계: 비로그인 개별 메모 검사
  const itemResponse = await check(
    '/api/notes/00000000-0000-4000-8000-000000000000', 'anonymous_item_read'
  );

  const attempts = [
    {
      attackId: 'static_note_exposure',
      expected: '정적 메모 노출 없음',
      observed: exposed
        ? '정적 메모 노출 확인'
        : `정적 메모 노출 없음 (HTTP ${staticResponse.status})`
    },
    {
      attackId: 'anonymous_api_read',
      expected: '비로그인 목록 조회 401 거부',
      observed: `비로그인 목록 요청 HTTP ${apiResponse.status}`
    },
    {
      attackId: 'invalid_login_token',
      expected: '잘못된 토큰 401 거부',
      observed: `잘못된 토큰 요청 HTTP ${invalidTokenResponse.status}`
    },
    {
      attackId: 'anonymous_item_read',
      expected: '비로그인 개별 조회 401 거부',
      observed: `비로그인 개별 요청 HTTP ${itemResponse.status}`
    }
  ];

  if (config.step >= 8) {
    // 실제 배포 주소에 보낸 비로그인 요청의 HTTP 상태만 기록한다.
    const noticeRead = await check('/api/announcements/stage8-notice-1',
      'anonymous_announcement_read');
    const teacherRead = await check('/api/teacher/stage8-test', 'unknown_teacher_route');

    attempts.push(
      {
        attackId: 'anonymous_announcement_read',
        expected: '비로그인 공지 조회 401 거부',
        observed: `비로그인 공지 요청 HTTP ${noticeRead.status}`
      },
      {
        attackId: 'announcement_write_rejected',
        expected: '공지 쓰기 POST 405 거부',
        observed: 'not_run'
      },
      {
        attackId: 'unknown_teacher_route',
        expected: '알 수 없는 강사 자료 경로 404 거부',
        observed: `강사 자료 경로 요청 HTTP ${teacherRead.status}`
      }
    );
  }

  if (config.step >= 10) {
    const restoreWrongMethod = await check('/api/restore-note', 'restore_get_rejected');
    attempts.push(
      {
        attackId: 'anonymous_restore_denied',
        expected: '비로그인 복구 POST 401 거부',
        observed: 'not_run'
      },
      {
        attackId: 'restore_get_rejected',
        expected: '복구 경로 GET 405 거부',
        observed: `복구 GET 요청 HTTP ${restoreWrongMethod.status}`
      }
    );
  }

  if (config.step >= 11) {
    const manifest = await check('/manifest.webmanifest', 'app_manifest_present');
    const offline = await check('/offline.html', 'public_offline_guidance');
    const deviceWithoutLogin = await check('/api/device', 'anonymous_device_status_denied');
    attempts.push(
      {
        attackId: 'app_manifest_present',
        expected: '설치 앱 manifest HTTP 200',
        observed: `설치 manifest 요청 HTTP ${manifest.status}`,
      },
      {
        attackId: 'public_offline_guidance',
        expected: '보호 자료 없는 오프라인 안내 HTTP 200',
        observed: `오프라인 안내 요청 HTTP ${offline.status}`,
      },
      {
        attackId: 'anonymous_device_status_denied',
        expected: '비로그인 기기 상태 401 거부',
        observed: `비로그인 기기 상태 요청 HTTP ${deviceWithoutLogin.status}`,
      },
      {
        attackId: 'anonymous_device_register_denied',
        expected: '비로그인 기기 등록 요청 401 거부',
        observed: 'not_run',
      },
    );
  }

  if (config.step >= 12) {
    const operations = await check('/api/operations', 'operations_summary_available');
    attempts.push({
      attackId: 'operations_summary_available',
      expected: '공개 구성 요약 HTTP 200, 실제 운영 기록 없으면 미확인',
      observed: `작전실 요약 요청 HTTP ${operations.status}`,
    });
  }

  return attempts;
}
