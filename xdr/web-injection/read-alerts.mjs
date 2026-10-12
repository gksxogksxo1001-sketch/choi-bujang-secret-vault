import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * xdr/fixtures/web-injection.json 에서 Wazuh 경보를 읽어
 * 시각, 출발 주소, 계정, 규칙 수준, 설명만 추출합니다.
 * 비밀값처럼 보이는 필드(URL 쿼리 본문 등)는 포함하지 않습니다.
 */
export async function readAlerts(fixturePath) {
  const targetPath = fixturePath || resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/web-injection.json');
  const raw = await readFile(targetPath, 'utf8');
  const fixture = JSON.parse(raw);
  const alerts = Array.isArray(fixture.alerts) ? fixture.alerts : [];

  return alerts.map(alert => ({
    timestamp: alert.timestamp ?? '',
    srcip: alert.data?.srcip ?? '',
    srcuser: alert.data?.srcuser ?? '(없음)',
    level: alert.rule?.level ?? 0,
    description: alert.rule?.description ?? '',
  }));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const records = await readAlerts();
    for (const item of records) {
      console.log(`[${item.timestamp}] ${item.srcip} | ${item.srcuser} | 레벨 ${item.level} | ${item.description}`);
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : '읽기 오류');
    process.exitCode = 1;
  }
}
