/**
 * xdr/exfiltration/patterns.json 에서 가져온 외부 유출(T1041·T1048) 악용 패턴 상수
 */
const PATTERNS = [
  {
    name: "처음 보는 목적지로 대용량 자료 연속 전송",
    condition: "짧은 시간에 다수의 자료나 대용량 바이트가 처음 보는 외부 목적지 또는 비표준 포트로 전송",
    rationale: "MITRE ATT&CK T1048(다른 프로토콜로 유출) 및 T1041(명령 통로로 유출)에 기반하여 내부 자료를 미인가 외부 서버로 대량 반출하는 유출 신호입니다."
  },
  {
    name: "업무 시간 밖 압축 파일 외부 반출",
    condition: "수업·업무 시간 밖에 대용량 전송이 반복되거나 압축 파일 묶음이 처음 보는 외부 주소로 반출",
    rationale: "MITRE ATT&CK T1048(다른 프로토콜로 유출)에 기반하여 탈취한 데이터를 압축해 감시가 적은 시간대나 낯선 주소로 빼돌리는 유출 신호입니다."
  },
  {
    name: "명령 통로를 통한 대용량 반복 유출",
    condition: "명령 통로로 같은 외부 목적지에 대용량 파일이나 자료실 묶음이 여러 차례 반복 전송",
    rationale: "MITRE ATT&CK T1041(명령 통로로 유출)에 기반하여 이미 연결된 명령·제어 통로를 통해 주요 자료를 외부로 반출하는 신호입니다."
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
  const bytes = Number(alert?.data?.bytes ?? 0);
  const count = Number(alert?.data?.count ?? 0);
  const desc = String(alert?.rule?.description ?? '');
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1041 = mitre.includes('T1041');

  let matchedReason = PATTERNS[0].name;
  if (desc.includes('시간 밖') || desc.includes('압축 파일')) {
    matchedReason = PATTERNS[1].name;
  } else if (desc.includes('명령 통로') || desc.includes('반복') || hasT1041) {
    matchedReason = PATTERNS[2].name;
  } else {
    matchedReason = PATTERNS[0].name;
  }

  // 1. 명확한 대용량 외부 반출·반복 유출 공격 (Level 10 이상 또는 50MB 이상 대용량 유출) -> block (confidence >= 0.85)
  if (level >= 10 || bytes >= 50000000 || count >= 8) {
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
