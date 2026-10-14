
export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].includes(config.step)) {
    throw new Error('지원하지 않는 점검 단계입니다.');
  }

  const app = new URL(config.publicAppUrl);

  if (
    app.protocol !== 'https:' ||
    app.hostname.endsWith('.example')
  ) {
    throw new Error('실제 HTTPS 배포 주소를 확인하세요.');
  }

  async function check(path, options = {}) {
    return fetch(new URL(path, app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      ...options
    });
  }

  // 정적 메모 노출 확인
  const staticResponse = await check('/data.json');

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
  const apiResponse = await check('/api/notes');

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
  const invalidTokenResponse = await check('/api/notes', {
    headers: {
      Authorization: 'Bearer invalid.token.value'
    }
  });

  // 3단계: 비로그인 개별 메모 검사
  const itemResponse = await check(
    '/api/notes/00000000-0000-4000-8000-000000000000'
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
    const noticeRead = await check('/api/announcements/stage8-notice-1');
    const noticeWrite = await check('/api/announcements/stage8-notice-1', {
      method: 'POST'
    });
    const teacherRead = await check('/api/teacher/stage8-test');

    attempts.push(
      {
        attackId: 'anonymous_announcement_read',
        expected: '비로그인 공지 조회 401 거부',
        observed: `비로그인 공지 요청 HTTP ${noticeRead.status}`
      },
      {
        attackId: 'announcement_write_rejected',
        expected: '공지 쓰기 POST 405 거부',
        observed: `공지 쓰기 요청 HTTP ${noticeWrite.status}`
      },
      {
        attackId: 'unknown_teacher_route',
        expected: '알 수 없는 강사 자료 경로 404 거부',
        observed: `강사 자료 경로 요청 HTTP ${teacherRead.status}`
      }
    );
  }

  if (config.step >= 10) {
    const restoreWithoutLogin = await check('/api/restore-note', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
    });
    const restoreWrongMethod = await check('/api/restore-note');
    attempts.push(
      {
        attackId: 'anonymous_restore_denied',
        expected: '비로그인 복구 POST 401 거부',
        observed: `비로그인 복구 요청 HTTP ${restoreWithoutLogin.status}`
      },
      {
        attackId: 'restore_get_rejected',
        expected: '복구 경로 GET 405 거부',
        observed: `복구 GET 요청 HTTP ${restoreWrongMethod.status}`
      }
    );
  }

  if (config.step >= 11) {
    const manifest = await check('/manifest.webmanifest');
    const offline = await check('/offline.html');
    const deviceWithoutLogin = await check('/api/device');
    const registerWithoutLogin = await check('/api/device', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'register-options' }),
    });
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
        observed: `비로그인 기기 등록 요청 HTTP ${registerWithoutLogin.status}`,
      },
    );
  }

  return attempts;
}
