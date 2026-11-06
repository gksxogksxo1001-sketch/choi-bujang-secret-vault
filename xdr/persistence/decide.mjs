/**
 * xdr/persistence/patterns.json 에서 가져온 지속성(서비스·예약 작업·시작 폴더) 악용 패턴 상수
 */
const PATTERNS = [
  {
    name: "서명 없는 새 서비스 등록 및 실행 파일 변경",
    condition: "평소 목록에 없거나 서명 없는 새 서비스가 임시 폴더 등의 실행 파일을 가리키며 등록·변경되거나 반복 발생",
    rationale: "MITRE ATT&CK T1543(시스템 프로세스 생성·변경)에 기반하여 재부팅 뒤에도 악성 프로그램이 시스템 서비스로 자동 실행되게 심어 두는 지속성 공격 신호입니다."
  },
  {
    name: "낯선 예약 작업 생성 및 임시 폴더 프로그램 실행",
    condition: "처음 보거나 임의 문자열 이름을 가진 예약 작업이 임시 폴더의 실행 파일을 수업 시간 밖 등에 실행하도록 등록",
    rationale: "MITRE ATT&CK T1053(예약 작업)에 기반하여 지정된 시각이나 주기마다 백도어·악성 실행 파일을 자동으로 다시 실행하려는 지속성 공격 신호입니다."
  },
  {
    name: "시작 폴더 내 미인가 프로그램 추가 및 변경",
    condition: "사용자 시작 폴더(Startup)에 평소 목록에 없는 실행 파일이 추가되거나 예약 작업과 함께 임시 파일을 가리키도록 변경",
    rationale: "MITRE ATT&CK T1543(시스템 프로세스 생성·변경) 및 T1053(예약 작업)에 기반하여 로그인·재시작 시 악성 코드가 다시 살아남도록 시작 경로를 변조하는 신호입니다."
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
  const desc = String(alert?.rule?.description ?? '');
  const path = String(alert?.data?.path ?? '');
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1543 = mitre.includes('T1543');
  const hasT1053 = mitre.includes('T1053');

  let matchedReason = PATTERNS[0].name;
  if (desc.includes('시작 폴더') || desc.includes('시작 프로그램') || desc.includes('시작 항목') || path.includes('Startup')) {
    matchedReason = PATTERNS[2].name;
  } else if (desc.includes('예약 작업') || (hasT1053 && !hasT1543)) {
    matchedReason = PATTERNS[1].name;
  } else if (desc.includes('서비스') || hasT1543) {
    matchedReason = PATTERNS[0].name;
  }

  // 1. 명확한 지속성 심기 공격 (Level 10 이상 또는 연속 서비스 등록 3건 이상) -> block (confidence >= 0.85)
  if (level >= 10 || count >= 3) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedReason
    };
  }

  // 2. 애매한 시도 / 단발성 주의 경보 (Level 5 ~ 9) -> alert (0.5 <= confidence < 0.85)
  if (level >= 5) {
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

