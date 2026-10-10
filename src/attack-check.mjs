
export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) {
    throw new Error('지원하지 않는 점검 단계입니다.');
  }

  const app = new URL(config.publicAppUrl);

  if (app.protocol !== 'https:' || app.hostname.endsWith('.example')) {
    throw new Error('실제 HTTPS 배포 주소를 확인하세요.');
  }

  // 공개 정적 JSON 확인
  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000)
  });

  let exposed = false;

  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      exposed = Array.isArray(data.notes) && data.notes.length > 0;
    } catch {
      exposed = false;
    }
  }

  if (config.step === 1) {
    return [{
      attackId: 'anonymous_note_read',
      expected: '비로그인 상태에서 가상 메모 공개 확인',
      observed: exposed
        ? '공개 가상 메모 확인'
        : `메모가 보이지 않음 (HTTP ${staticResponse.status})`
    }];
  }

  // 2단계 서버 API 확인
  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000)
  });

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
      expected: '정적 JSON에서 가상 메모가 보이지 않아야 함',
      observed: exposed
        ? '정적 JSON에 메모가 여전히 공개됨'
        : `정적 메모 노출 없음 (HTTP ${staticResponse.status})`
    },
    {
      attackId: 'anonymous_api_read',
      expected: '서버 API의 비로그인 접근 가능 여부 확인',
      observed: noteCount === 4
        ? '비로그인 API에서 메모 4건 확인 - 공개 API 약점'
        : `메모 4건 확인 실패 (HTTP ${apiResponse.status})`
    }
  ];
}
