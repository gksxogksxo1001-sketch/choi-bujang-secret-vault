// 9단계 도플갱어 탐지 및 권한 회수 제안 함수입니다.
// 엔진이 검증한 가상 사건을 전달받아 10분 구간 내 다량 조회(120건 초과)를 탐지합니다.
// 브라우저가 보낸 임의의 사용자 번호는 믿지 않으며, 실명·토큰·본문은 저장하지 않습니다.
export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const WINDOW_MS = 10 * 60 * 1000; // 10분 (600,000ms)
  const userEvents = new Map();

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    if (event.method !== 'GET') continue;

    const sub = event.identity?.sub;
    if (typeof sub !== 'string' || !sub.trim()) continue;

    const at = event.at;
    const time = typeof at === 'string' || typeof at === 'number' ? new Date(at).getTime() : NaN;
    if (Number.isNaN(time)) continue;

    if (!userEvents.has(sub)) {
      userEvents.set(sub, []);
    }
    userEvents.get(sub).push(time);
  }

  for (const [sub, times] of userEvents.entries()) {
    times.sort((a, b) => a - b);

    let left = 0;
    for (let right = 0; right < times.length; right++) {
      while (times[right] - times[left] > WINDOW_MS) {
        left++;
      }

      // 같은 사용자의 10분 구간 내 GET 조회가 120건을 넘을 때만 회수 제안
      if (right - left + 1 > 120) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject: sub,
        };
      }
    }
  }

  return { action: 'observe' };
}
