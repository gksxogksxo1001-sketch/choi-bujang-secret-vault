// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step < 1 || config.step > 6) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1 || config.step === 2) {
    const endpoint = config.step === 1 ? '/data.json' : '/api/notes';
    const response = await fetch(new URL(endpoint, app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  // 3~5단계 점검 항목 구성
  const checks = [];

  // 비로그인 요청 시 토큰 부재로 401 거부되는지 점검
  const response = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const blocked = response.status === 401;
  checks.push({
    attackId: 'anonymous_note_read',
    expected: '비로그인 요청 시 가상 메모 접근 차단 (HTTP 401)',
    observed: blocked
      ? `비로그인 요청이 정상적으로 거부됨 (HTTP ${response.status})`
      : `비로그인 요청이 거부되지 않음 (HTTP ${response.status})`
  });

  // 5단계: 원본 자료 저장소(originalApiUrl) 직접 접근 거부 확인
  if (config.step >= 5 && config.originalApiUrl) {
    try {
      const originRes = await fetch(config.originalApiUrl, {
        signal: AbortSignal.timeout(10000),
      });
      const originBlocked = !originRes.ok;
      checks.push({
        attackId: 'direct_storage_read',
        expected: '원본 자료 저장소 직접 요청 차단',
        observed: originBlocked
          ? `직접 요청이 정상적으로 거부됨 (HTTP ${originRes.status})`
          : `직접 요청으로 자료가 노출됨 (HTTP ${originRes.status})`
      });
    } catch {
      checks.push({
        attackId: 'direct_storage_read',
        expected: '원본 자료 저장소 직접 요청 차단',
        observed: '직접 요청 연결 거부됨'
      });
    }
  }

  // 6단계: 미등록 기기 차단 점검 (심판 검증 항목으로 로컬은 미실행 기록)
  if (config.step >= 6) {
    checks.push({
      attackId: 'unregistered_device_access',
      expected: '미등록 기기 요청 차단 (device_not_registered)',
      observed: '미실행 (심판 검증 항목)'
    });
  }

  return checks;
}
