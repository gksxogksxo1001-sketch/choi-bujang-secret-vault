// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

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

  const signals = inspectSignals(request);
  const recentEvents = inspectRecentEvents(request);

  // 2. 평소와 다른 시각, 처음 보는 네트워크, 대량 자료 조회의 복합 이상 감지
  // 지역(region) 단독으로 영구 차단하지 않고 복합 조건일 때 추가 확인(step_up) 요구
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

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: isSuspicious ? ['step_up_required'] : ['device_registered'],
  };
}
