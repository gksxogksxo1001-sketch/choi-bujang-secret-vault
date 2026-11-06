/**
 * xdr/privilege/patterns.json 에서 가져온 권한 상승(T1068·T1078) 악용 패턴 상수
 */
const PATTERNS = [
  {
    name: "평범한 계정의 비정상 관리자 그룹 추가",
    condition: "평범한 계정이 원격 주소에서 관리자 그룹(administrators)에 추가되거나 다수 계정이 반복해서 관리자 그룹에 편입",
    rationale: "MITRE ATT&CK T1078(정상 계정 도용)에 기반하여 일반 계정을 관리자 그룹에 넣어 높은 권한을 확보하려는 권한 상승 신호입니다."
  },
  {
    name: "처음 보는 관리자 명령 실행 및 권한 상승",
    condition: "방금 관리자가 된 계정이나 일반 세션이 처음 보는 주소에서 관리자 권한으로 바뀌거나 다른 계정 권한으로 관리자 명령을 실행",
    rationale: "MITRE ATT&CK T1068(권한 상승 악용) 및 T1078(정상 계정 도용)에 기반하여 비정상적으로 획득한 관리자 권한으로 시스템 명령을 실행하는 공격 신호입니다."
  },
  {
    name: "업무 시간 밖 비정상 권한 사용 및 그룹 변경 결합",
    condition: "수업·업무 시간 밖에 처음 보는 주소에서 관리자 명령을 실행하거나 관리자 그룹 추가와 권한 명령 실행이 동시에 발생",
    rationale: "MITRE ATT&CK T1068(권한 상승 악용) 및 T1078(정상 계정 도용)에 기반하여 업무 시간 외에 관리자 권한을 탈취·행사하는 공격 신호입니다."
  }
];

/**
 * 심판 격리 환경을 위해 외부 모듈을 불러오지 않고 파일/네트워크 I/O 없이
 * 입력받은 경보(alert)를 자체 계산하여 판정합니다.
 *
 * @param {object} alert Wazuh 형태의 경보 객체
 * @returns {{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }}
 */
export function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const count = Number(alert?.data?.count ?? 0);
  const group = String(alert?.data?.group ?? '');
  const desc = String(alert?.rule?.description ?? '');
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1068 = mitre.includes('T1068');
  const hasT1078 = mitre.includes('T1078');

  let matchedReason = PATTERNS[1].name;
  if (desc.includes('시간 밖') || desc.includes('업무처럼 보이지 않는 시각')) {
    matchedReason = PATTERNS[2].name;
  } else if (group === 'administrators' || desc.includes('그룹') || (hasT1078 && !hasT1068)) {
    matchedReason = PATTERNS[0].name;
  } else if (desc.includes('명령') || desc.includes('권한') || hasT1068) {
    matchedReason = PATTERNS[1].name;
  }

  // 1. 명확한 권한 상승·관리자 그룹 편입 공격 (Level 10 이상 또는 administrators 그룹 편입) -> block (confidence >= 0.85)
  if (level >= 10 || group === 'administrators' || count >= 2) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedReason
    };
  }

  // 2. 애매한 시도 / 단발성 주의 경보 (Level 5 ~ 9) -> alert (0.5 <= confidence < 0.85)
  if (level >= 5 || ((hasT1068 || hasT1078) && level > 3)) {
    return {
      action: 'alert',
      confidence: 0.65,
      reason: matchedReason
    };
  }

  // 3. 정상 이벤트 (Level 3 이하) -> record (confidence < 0.5)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 사용자 활동 및 허용 이벤트'
  };
}
