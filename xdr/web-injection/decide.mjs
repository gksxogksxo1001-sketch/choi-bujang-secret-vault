/**
 * xdr/web-injection/patterns.json 에서 가져온 웹 주입 공격 패턴 상수
 */
const PATTERNS = [
  {
    name: "요청 인자 내 SQL 구문 반복 주입",
    condition: "동일 출발 주소(srcip)에서 요청 인자(URL/파라미터)에 SQL 구문 및 데이터베이스 조회를 이어 붙이는 시도가 반복 발생",
    rationale: "MITRE ATT&CK T1190(외부 공개 앱 악용)에 기반하여 웹 애플리케이션의 입력 검증 미흡을 노리고 데이터베이스를 비정상 조작하려는 SQL 주입 공격 신호입니다."
  },
  {
    name: "요청 인자 내 스크립트 태그 삽입 반복",
    condition: "동일 출발 주소(srcip)에서 요청 인자에 스크립트 태그나 스크립트 삽입 표기가 반복 발생",
    rationale: "MITRE ATT&CK T1190(외부 공개 앱 악용)에 기반하여 사용자 브라우저 또는 웹 애플리케이션에서 임의 스크립트를 실행시키려는 스크립트 주입 공격 신호입니다."
  },
  {
    name: "상위 디렉터리 경로 거슬러 올라가기(../) 반복",
    condition: "동일 출발 주소(srcip)에서 파일/경로 인자에 상위 경로를 거슬러 올라가는 표기(../) 및 경로 이탈 시도가 반복 발생",
    rationale: "MITRE ATT&CK T1190(외부 공개 앱 악용)에 기반하여 웹 서버의 제한된 디렉터리 외부 시스템 파일에 임의로 접근하려는 디렉터리 탐색 공격 신호입니다."
  }
];

/**
 * 심판 격리 환경을 위해 import/require 및 파일/네트워크 I/O 없이
 * 입력받은 웹 경보(alert)를 자체 계산하여 판정합니다.
 *
 * @param {object} alert Wazuh 형태의 웹 경보 객체
 * @returns {{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }}
 */
export function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const count = Number(alert?.data?.count ?? 0);
  const desc = String(alert?.rule?.description ?? '');
  const url = String(alert?.data?.url ?? '');
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1190 = mitre.includes('T1190');

  // 1. 명확한 반복적 주입 공격 (Level 10 이상 또는 반복 8회 이상) -> block
  if (level >= 10 || count >= 8) {
    let matchedReason = PATTERNS[0].name;

    if (desc.includes('스크립트') || url.includes('script')) {
      matchedReason = PATTERNS[1].name;
    } else if (desc.includes('경로') || desc.includes('명령') || url.includes('path') || url.includes('up')) {
      matchedReason = PATTERNS[2].name;
    } else if (desc.includes('SQL') || desc.includes('데이터베이스') || url.includes('sql')) {
      matchedReason = PATTERNS[0].name;
    }

    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedReason
    };
  }

  // 2. 단발성 의심 표기 / 애매한 시도 (Level 5 이상 또는 T1190 주의 경보) -> alert
  if (level >= 5 || (hasT1190 && level > 3)) {
    return {
      action: 'alert',
      confidence: 0.65,
      reason: '단발성 의심 표기 및 주의 요망 요청'
    };
  }

  // 3. 정상 이벤트 (Level 3 이하) -> record
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 사용자 활동 및 허용 이벤트'
  };
}
