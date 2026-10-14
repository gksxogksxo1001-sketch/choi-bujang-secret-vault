// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step < 1 || config.step > 12) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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

  // 격리 환경 번들 통과: 외부 요청 0건으로 배포 주소 유효성만 검증하고 모든 점검 항목을 not_run으로 반환
  const checks = [
    {
      attackId: 'anonymous_note_read',
      expected: '비로그인 요청 시 가상 메모 접근 차단 (HTTP 401)',
      observed: 'not_run'
    }
  ];

  if (config.step >= 5) {
    checks.push({
      attackId: 'direct_storage_read',
      expected: '원본 자료 저장소 직접 요청 차단',
      observed: 'not_run'
    });
  }

  if (config.step >= 6) {
    checks.push({
      attackId: 'unregistered_device_access',
      expected: '미등록 기기 요청 차단 (device_not_registered)',
      observed: 'not_run'
    });
  }

  if (config.step >= 7) {
    checks.push({
      attackId: 'step_up_reauth_check',
      expected: '복합 이상 접속 시 추가 확인(재인증) 전 차단 및 새 요청 허용',
      observed: 'not_run'
    });
  }

  if (config.step >= 8) {
    checks.push({
      attackId: 'cross_zone_access_check',
      expected: '타인 소유 메모 및 다른 구역 접근 차단',
      observed: 'not_run'
    });
  }

  if (config.step >= 9) {
    checks.push({
      attackId: 'burst_read_detection_check',
      expected: '10분 내 120건 초과 다량 조회 탐지 및 회수 제안(propose_revocation)',
      observed: 'not_run'
    });
  }

  if (config.step >= 10) {
    checks.push({
      attackId: 'single_note_restore_check',
      expected: '환경 변수 사본 기반 이중 해시 검증 및 비인가 본문 요청 차단',
      observed: 'not_run'
    });
  }

  if (config.step >= 11) {
    checks.push({
      attackId: 'device_approval_and_vault_lock_check',
      expected: '승인 전 보호 자료 노출 차단 및 서버 확인 기기만 자료실 해제',
      observed: 'not_run'
    });
  }

  if (config.step >= 12) {
    checks.push({
      attackId: 'invasion_41_attacks_defense',
      expected: '41종 침투 공격 종합 방어 및 작전실 실측 연동',
      observed: 'not_run'
    });
  }

  return checks;
}
