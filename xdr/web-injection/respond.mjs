import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, '../..');
const ALERTS_LOG_PATH = resolve(ROOT_DIR, 'xdr/alerts.log');

/**
 * 웹 주입 차단 후보(block)만 추출하여 ZTNA 판정기 거부 규칙으로 변환합니다.
 * 알림(alert 및 block)은 xdr/alerts.log 에 기록합니다.
 *
 * @param {Array} alerts Wazuh 경보 목록
 * @param {number} ttlSeconds 차단 규칙 유효 시간 (기본 3600초)
 * @returns {Promise<Array>} ZTNA 거부 규칙 목록
 */
export async function processAndRespond(alerts, ttlSeconds = 3600) {
  const denyRules = [];
  const logEntries = [];
  const now = new Date();

  await mkdir(dirname(ALERTS_LOG_PATH), { recursive: true });

  for (const alert of alerts) {
    const decision = decide(alert);
    const alertId = alert?.id || 'unknown';
    const srcip = alert?.data?.srcip || 'unknown';
    const srcuser = alert?.data?.srcuser || '(없음)';

    // 1. 알림은 alert, block 모두 xdr/alerts.log 에 기록 (비밀값 없는 요약 정보만 기록)
    if (decision.action === 'alert' || decision.action === 'block') {
      const logLine = `[${now.toISOString()}] [${decision.action.toUpperCase()}] alertId=${alertId} ip=${srcip} user=${srcuser} confidence=${decision.confidence} reason="${decision.reason}"\n`;
      logEntries.push(logLine);
    }

    // 2. 오직 명확한 차단 후보(block)만 거부 규칙으로 생성 (정상 및 단순 주의는 제외)
    if (decision.action === 'block') {
      const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
      denyRules.push({
        ruleId: `xdr_web_injection_${alertId}`,
        alertId: alertId,
        ip: srcip,
        targetUser: srcuser,
        reason: decision.reason,
        confidence: decision.confidence,
        expiresAt: expiresAt,
        createdAt: now.toISOString(),
      });
    }
  }

  // 로그 파일에 한 줄씩 추가
  if (logEntries.length > 0) {
    await appendFile(ALERTS_LOG_PATH, logEntries.join(''), 'utf8');
  }

  return denyRules;
}

/**
 * 기존 ZTNA 판정기에 XDR 웹 주입 차단 검사를 더하는 연결 래퍼
 * 기존 규칙을 대체하지 않고, 사전 위협 차단 단계만 추가합니다.
 *
 * @param {Function} baseDecide 기존 ZTNA 판정기 함수
 * @param {Array} denyRules 활성 거부 규칙 목록
 * @returns {Function} 검증 단계가 추가된 ZTNA 판정기 함수
 */
export function createGuardedDecider(baseDecide, denyRules = []) {
  return async function guardedDecide(request) {
    const now = new Date().toISOString();
    // 요청 IP 확인
    const requestIp = request?.signals?.sourceIp
      || request?.signals?.source
      || request?.clientIp
      || request?.ip
      || '';

    // 만료 시각 이전이고 IP가 일치하는 거부 규칙 탐색
    const matched = denyRules.find(r =>
      r.ip && (r.ip === requestIp || (typeof requestIp === 'string' && requestIp.includes(r.ip)))
      && r.expiresAt > now
    );

    if (matched) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request?.requestId || 'req-blocked',
        decision: 'deny',
        reasonCode: 'xdr_threat_blocked',
        ruleIds: [matched.ruleId],
        alertId: matched.alertId,
        expiresAt: matched.expiresAt,
      };
    }

    // 공격 IP가 아니면 기존 판정기의 규칙에 그대로 위임
    return baseDecide(request);
  };
}

// 직접 실행 시: 시험 경보를 읽어 거부 규칙을 생성하고 정상/공격 요청을 흘려 검증
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const fixturePath = resolve(ROOT_DIR, 'xdr/fixtures/web-injection.json');
    const fixtureRaw = await readFile(fixturePath, 'utf8');
    const { alerts } = JSON.parse(fixtureRaw);

    const denyRules = await processAndRespond(alerts);
    console.log(`[XDR 응답] 생성된 거부 규칙 수: ${denyRules.length}건 (차단 후보만 포함, 만료 시각 및 근거 경보 번호 부착)`);

    // 정상 요청을 통과시키는 기본 가상 판정기
    const defaultDecider = async (req) => ({
      schema: 'aleph.decision.v1',
      requestId: req.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    });

    const guarded = createGuardedDecider(defaultDecider, denyRules);

    // 1. 명확한 공격 IP (wi-01 의 203.0.113.10) 시험
    const attackReq = {
      requestId: 'test-attack-01',
      clientIp: '203.0.113.10',
      signals: { source: '203.0.113.10' },
    };
    const attackRes = await guarded(attackReq);

    // 2. 정상 사용자 IP (wi-18 의 192.0.2.70) 시험
    const normalReq = {
      requestId: 'test-normal-01',
      clientIp: '192.0.2.70',
      signals: { source: '192.0.2.70' },
    };
    const normalRes = await guarded(normalReq);

    console.log(`[시험 결과] 공격 IP(${attackReq.clientIp}): ${attackRes.decision} (규칙: ${attackRes.ruleIds?.[0]}, 근거: ${attackRes.alertId})`);
    console.log(`[시험 결과] 정상 IP(${normalReq.clientIp}): ${normalRes.decision} (판정: ${normalRes.reasonCode})`);

    if (attackRes.decision === 'deny' && normalRes.decision === 'allow') {
      console.log('=> 검증 성공: 명확한 공격만 거부 규칙으로 막히고 정상 요청은 통과했습니다.');
    } else {
      console.error('=> 검증 실패: 판정 결과가 올바르지 않습니다.');
      process.exitCode = 1;
    }
  } catch (error) {
    console.error('실행 중 오류 발생:', error);
    process.exitCode = 1;
  }
}
