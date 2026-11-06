/**
 * xdr/known-cve/patterns.json 에서 가져온 공개 취약점(CVE-2021-44228) 악용 패턴 상수
 */
const PATTERNS = [
  {
    name: "요청 머리글 내 원격 조회 구문(jndi 형태) 삽입",
    condition: "요청 머리글(useragent 등)에 CVE-2021-44228 악용 형태인 원격 조회 구문(jndi 형태)이 포함되거나 반복 발생",
    rationale: "CVE-2021-44228 형태 요청 및 MITRE ATT&CK T1190(외부 공개 앱 악용)에 기반하여 로그 기록 시 외부에서 원격 명령을 불러오려는 공격 신호입니다."
  },
  {
    name: "요청 인자 내 원격 조회 구문(jndi 형태) 삽입",
    condition: "요청 주소 인자(url/파라미터)에 CVE-2021-44228 악용 형태인 원격 조회 구문(jndi 형태)이 포함되거나 반복 발생",
    rationale: "CVE-2021-44228 형태 요청 및 MITRE ATT&CK T1190(외부 공개 앱 악용)에 기반하여 요청 인자를 로그에 남기게 해 원격 조회를 유발하는 공격 신호입니다."
  },
  {
    name: "알려진 취약점 점검 도구의 흔적 및 CVE-2021-44228 결합",
    condition: "알려진 취약점 점검 도구의 흔적(probe 등)과 CVE-2021-44228 형태 원격 조회 구문이 함께 탐지",
    rationale: "CVE-2021-44228 형태 요청 및 MITRE ATT&CK T1190(외부 공개 앱 악용)에 기반하여 취약점 점검 도구로 대상 서버의 악용 가능 여부를 탐색·공격하는 신호입니다."
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
  const url = String(alert?.data?.url ?? '');
  const useragent = String(alert?.data?.useragent ?? '');
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1190 = mitre.includes('T1190');
  const hasJndiLookup = url.includes('jndi:') || useragent.includes('jndi:');

  // 1. 명확한 CVE-2021-44228 원격 조회 공격 (Level 10 이상 또는 실제 jndi 원격 조회 구문 포함) -> block (confidence >= 0.85)
  if (level >= 10 || hasJndiLookup || count >= 4) {
    let matchedReason = PATTERNS[1].name;

    if (desc.includes('점검 흔적') || url.includes('probe=')) {
      matchedReason = PATTERNS[2].name;
    } else if (useragent.includes('jndi:') || desc.includes('머리글')) {
      matchedReason = PATTERNS[0].name;
    } else if (url.includes('jndi:') || desc.includes('인자')) {
      matchedReason = PATTERNS[1].name;
    }

    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedReason
    };
  }

  // 2. 애매한 시도 / 단발성 취약점 키워드·점검 주의 경보 (Level 5 ~ 9 또는 T1190 주의 경보) -> alert (0.5 <= confidence < 0.85)
  if (level >= 5 || (hasT1190 && level > 3)) {
    return {
      action: 'alert',
      confidence: 0.65,
      reason: PATTERNS[2].name
    };
  }

  // 3. 정상 이벤트 (Level 3 이하) -> record (confidence < 0.5)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 사용자 활동 및 허용 이벤트'
  };
}

