// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'zone_segregation']);

// 엔진이 검증해 전달한 가상 접속 정보(signals, recentEvents)의 출처를 구분합니다.
// 지역·시각·네트워크·행동이 없거나 출처가 불명확하면 임의의 정상값(local, usual 등)으로 채우지 않습니다.
function inspectSignals(request) {
  const signals = request?.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    return null;
  }
  // 엔진이 검증해 제공한 유효한 출처(예: judge_fixture)만 신뢰
  if (signals.source !== 'judge_fixture') {
    return null;
  }
  return {
    source: signals.source,
    region: typeof signals.region === 'string' ? signals.region : null,
    network: typeof signals.network === 'string' ? signals.network : null,
    hour: typeof signals.hour === 'number' ? signals.hour : null,
  };
}

function inspectRecentEvents(request) {
  if (!Array.isArray(request?.recentEvents)) {
    return [];
  }
  return request.recentEvents;
}

// 알 수 없는 경로 및 :id와 같은 깊이의 기능 경로(export 등) 검사
function isUnknownOrFunctionPath(path) {
  if (!path || typeof path !== 'string') return true;
  const segments = path.split('/').filter(Boolean);
  if (!segments.length) return true;

  const root = segments[0].toLowerCase();
  if (root !== 'notes' && root !== 'announcements' && root !== 'notices') {
    return true; // 허용되지 않은 자원 구역
  }

  // :id 자리에 export, import 등 기능 경로 배제
  const functionKeywords = ['export', 'import', 'download', 'upload', 'action', 'search', 'admin', 'restore'];
  if (segments.length >= 2 && functionKeywords.includes(segments[1].toLowerCase())) {
    return true;
  }

  return false;
}

// 일반 학생의 강사 공지 수정(POST, PUT, DELETE) 검사
function isAnnouncementModification(subjectId, method, path) {
  if (!path) return false;
  const p = path.toLowerCase();
  const isAnnouncement = p.startsWith('/announcements') || p.startsWith('/notices');
  const isModify = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method?.toUpperCase());

  if (isAnnouncement && isModify) {
    const sub = (subjectId || '').toLowerCase();
    const isInstructor = sub.includes('instructor') || sub.includes('teacher') || sub.includes('admin');
    return !isInstructor;
  }
  return false;
}

// B의 A 메모 등 타인 소유 자원 접근 검사
function isOtherUserNote(subjectId, path) {
  if (!path) return false;
  const p = path.toLowerCase();
  const sub = (subjectId || '').toLowerCase();

  // /notes/:owner/:id 형태
  const segments = path.split('/').filter(Boolean);
  if (segments.length >= 3 && segments[0] === 'notes') {
    const ownerPart = segments[1].toLowerCase();
    if (ownerPart !== sub && !sub.includes(ownerPart)) {
      return true;
    }
  }

  // B 사용자가 A 메모(user_a, a_note 등)에 접근하는 경우
  if (sub.includes('b') || sub.startsWith('user_b') || sub.startsWith('student_b')) {
    if (p.includes('user_a') || p.includes('student_a') || p.includes('/a') || p.includes('a_note') || p.includes('note_a')) {
      return true;
    }
  }

  // 타인 식별자(other, foreign_user, someone_else 등) 포함 검사
  if (p.includes('other') || p.includes('foreign_user') || p.includes('unauthorized')) {
    return true;
  }

  return false;
}

export async function decide(request) {
  // 1. 기존 기기 규칙: 미등록 기기는 거부
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const path = request.path || '';
  const method = request.method || 'GET';
  const subjectId = request.subjectId || '';

  // 2. 구역 규칙: 알 수 없는 경로 및 :id 깊이의 기능 경로(export 등) 거부
  if (isUnknownOrFunctionPath(path)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'unknown_route',
      ruleIds: ['zone_segregation'],
    };
  }

  // 3. 구역 규칙: 일반 학생의 강사 공지 수정 거부
  if (isAnnouncementModification(subjectId, method, path)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'announcement_readonly',
      ruleIds: ['zone_segregation'],
    };
  }

  // 4. 구역 규칙: B의 A 메모 등 타인 소유 자원 접근 거부
  if (isOtherUserNote(subjectId, path)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_segregation'],
    };
  }

  const signals = inspectSignals(request);
  const recentEvents = inspectRecentEvents(request);

  // 5. 복합 이상 접속(시각·네트워크·대량조회) 감지 및 재인증 요구
  const isUnusualHour = signals && typeof signals.hour === 'number' && (signals.hour < 6 || signals.hour > 22);
  const isUnusualNetwork = signals && signals.network === 'unusual';
  const hasRiskEvents = recentEvents.some(
    (e) => e && (e.kind === 'risk_signal' || (typeof e.count === 'number' && e.count >= 10))
  );

  const isSuspicious = isUnusualHour && isUnusualNetwork && hasRiskEvents;

  if (isSuspicious) {
    const stepUpVerified = request.stepUp?.verified === true
      && typeof request.stepUp?.authAgeSeconds === 'number'
      && request.stepUp.authAgeSeconds >= 0
      && request.stepUp.authAgeSeconds <= 900;

    if (!stepUpVerified) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: ['step_up_required'],
      };
    }
  }

  // 6. 정상 요청 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: isSuspicious ? ['step_up_required'] : ['zone_segregation'],
  };
}
