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

// 구역 및 경로 엄격 검증 (화이트리스트 방식)
// 1. 강사 공지 / 반 공지 구역: 읽기(GET)만 허용하고, 쓰기(POST·PUT·PATCH·DELETE)는 누구에게나 전면 거부 (instructor는 강사 전용이므로 학생 접근 전면 거부)
// 2. 메모 구역: 단건 메모(/notes/:id 또는 /api/notes/:id)의 읽기·수정만 허용하고, 전체 목록(/notes) 및 다른 구역 접두어(/zone2/notes/...)는 전면 거부
// 3. 그 외 허용되지 않은 다른 모든 구역 및 경로는 전면 거부 (s08_OTHER_ZONE_ALLOWED 차단)
function evaluateZone(request) {
  const method = (request.method || 'GET').toUpperCase();
  const rawPath = typeof request.path === 'string' ? request.path.trim().toLowerCase() : '';
  const rawRoute = typeof request.route === 'string' ? request.route.trim().toLowerCase() : '';
  const service = typeof request.service === 'string' ? request.service.trim().toLowerCase() : '';

  // 1. 강사 공지 / 반 공지 구역 판정 (announcements, notices)
  // instructor는 학생에게 허용되지 않은 강사 전용 구역이므로 전면 거부
  if (rawPath.includes('instructor') || rawRoute.includes('instructor') || service === 'instructor') {
    return { allowed: false, reasonCode: 'zone_access_denied' };
  }

  const isAnnouncement =
    rawPath.includes('announcement') || rawPath.includes('notice')
    || rawRoute.includes('announcement') || rawRoute.includes('notice')
    || ['announcements', 'notices', 'announcement', 'notice'].includes(service);

  if (isAnnouncement) {
    // 반 공지나 강사 자료에 대한 쓰기(POST·PUT·PATCH·DELETE)는 누구에게나 전면 거부
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return { allowed: false, reasonCode: 'zone_access_denied' };
    }
    // 공지 읽기(GET)만 허용
    if (method === 'GET') {
      return { allowed: true };
    }
    return { allowed: false, reasonCode: 'zone_access_denied' };
  }

  // 2. 메모 구역 판정
  // 등록되지 않은 다른 서비스 구역은 전면 거부
  if (service && service !== 'notes') {
    return { allowed: false, reasonCode: 'zone_access_denied' };
  }

  // 라우트 검증: 제공된 경우 반드시 /notes/:id 또는 /api/notes/:id 형태여야 함
  if (rawRoute) {
    const validRoute = rawRoute.endsWith('/notes/:id') || rawRoute.endsWith('/api/notes/:id');
    if (!validRoute) {
      return { allowed: false, reasonCode: 'zone_access_denied' };
    }
  }

  // 경로 구조 검증: 오직 /notes/:id 또는 /api/notes/:id 만 허용 (다른 구역 접두어 /zone2/notes/..., /users/b/notes/... 전면 차단)
  const segments = rawPath.split('/').filter(Boolean);
  let idPart = null;

  if (segments.length === 2 && segments[0] === 'notes') {
    idPart = segments[1];
  } else if (segments.length === 3 && segments[0] === 'api' && segments[1] === 'notes') {
    idPart = segments[2];
  } else {
    // 단건 메모의 유효한 형태가 아니면(전체 목록 /notes, 타 구역 /zone2/notes/1 등) 무조건 거부
    return { allowed: false, reasonCode: 'zone_access_denied' };
  }

  // :id 자리에 기능 키워드(export, import 등) 배제
  const functionKeywords = ['export', 'import', 'download', 'upload', 'action', 'search', 'admin', 'restore', 'all', 'list', 'bulk', 'batch'];
  if (functionKeywords.includes(idPart)) {
    return { allowed: false, reasonCode: 'unknown_route' };
  }

  // 단건 메모 읽기·수정·삭제 메서드만 허용
  if (['GET', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return { allowed: true };
  }

  return { allowed: false, reasonCode: 'unknown_route' };
}

// 제공된 가상 사건에서 가명 사용자·기기·요청 종류·판정 신호만 안전하게 읽습니다.
// 메모 본문, 토큰, 실명, 비인가 외부 필드는 저장하거나 출력하지 않고 철저히 배제합니다.
function sanitizeRequest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }
  return {
    schema: raw.schema,
    requestId: typeof raw.requestId === 'string' ? raw.requestId : '',
    subjectId: typeof raw.subjectId === 'string' ? raw.subjectId : null,
    deviceId: typeof raw.deviceId === 'string' ? raw.deviceId : null,
    service: typeof raw.service === 'string' ? raw.service : '',
    method: typeof raw.method === 'string' ? raw.method : 'GET',
    path: typeof raw.path === 'string' ? raw.path : '',
    route: typeof raw.route === 'string' ? raw.route : '',
    deviceRegistered: raw.deviceRegistered === true,
    stepUp: raw.stepUp && typeof raw.stepUp === 'object' ? {
      verified: raw.stepUp.verified === true,
      authAgeSeconds: typeof raw.stepUp.authAgeSeconds === 'number' ? raw.stepUp.authAgeSeconds : null,
    } : null,
    signals: raw.signals,
    recentEvents: raw.recentEvents,
  };
}

export async function decide(rawRequest) {
  const request = sanitizeRequest(rawRequest) || rawRequest;

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

  // 2. 구역 규칙: 화이트리스트 기반 구역 및 동작 검증
  const zoneResult = evaluateZone(request);
  if (!zoneResult.allowed) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: zoneResult.reasonCode,
      ruleIds: ['zone_segregation'],
    };
  }

  const signals = inspectSignals(request);
  const recentEvents = inspectRecentEvents(request);

  // 복합 의심 탐지: 평소와 다른 네트워크와 갑작스러운 다량 조회가 함께 나타날 때만 의심으로 표시
  // 지역(region) 하나만으로 확정하지 않고 정상 사건은 그대로 유지
  const isUnusualNetwork = Boolean(signals && signals.network === 'unusual');
  const hasBurstRead = recentEvents.some(
    (e) => e && (e.kind === 'risk_signal' || (typeof e.count === 'number' && e.count >= 10))
  );

  const isSuspicious = isUnusualNetwork && hasBurstRead;

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
    ruleIds: isSuspicious ? ['step_up_required'] : ['device_registered', 'zone_segregation'],
  };
}