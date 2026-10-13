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

// 여러 사람의 자료를 한꺼번에 여는 메모 전체 목록 경로(/notes) 거부 (단건 /notes/:id만 허용)
function isBulkNoteListPath(path, route) {
  if (route === 'GET /notes') return true;
  const segments = (path || '').split('/').filter(Boolean);
  if (segments.length === 1 && segments[0].toLowerCase() === 'notes') {
    return true;
  }
  return false;
}

// 요청 계약에는 역할이 없으므로 반 공지·강사 자료에 대한 쓰기(POST, PUT, PATCH, DELETE)는 누구에게나 거부
function isAnnouncementModification(method, path) {
  if (!path) return false;
  const p = path.toLowerCase();
  const isAnnouncement = p.startsWith('/announcements') || p.startsWith('/notices');
  const isModify = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method?.toUpperCase());
  return isAnnouncement && isModify;
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
  const route = request.route || '';

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

  // 3. 구역 규칙: 메모 전체 목록처럼 여러 사람의 자료를 한꺼번에 여는 경로 거부
  if (isBulkNoteListPath(path, route)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_segregation'],
    };
  }

  // 4. 구역 규칙: 반 공지·강사 자료에 대한 쓰기는 누구에게나 거부
  if (isAnnouncementModification(method, path)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'announcement_readonly',
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
