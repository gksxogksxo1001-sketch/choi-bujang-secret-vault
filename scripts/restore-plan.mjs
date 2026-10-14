import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const backupJsonPath = join(root, 'backups', 'step10', 'safe-policy.json');
const backupShaPath = join(root, 'backups', 'step10', 'safe-policy.sha256');
const currentPolicyPath = join(root, 'src', 'decider.mjs');

async function main() {
  process.stdout.write('=== 10단계 안전 정책 복원 계획 (restore:plan) ===\n\n');

  if (!existsSync(backupJsonPath) || !existsSync(backupShaPath)) {
    throw new Error('안전 정책 사본 파일(backups/step10/safe-policy.json 또는 .sha256)이 없습니다.');
  }

  const rawJson = readFileSync(backupJsonPath, 'utf8');
  const expectedHash = readFileSync(backupShaPath, 'utf8').trim().toLowerCase();
  const computedHash = createHash('sha256').update(rawJson, 'utf8').digest('hex');

  const bufExpected = Buffer.from(expectedHash, 'hex');
  const bufComputed = Buffer.from(computedHash, 'hex');

  if (bufExpected.length !== bufComputed.length || !timingSafeEqual(bufExpected, bufComputed)) {
    throw new Error(`안전 정책 사본 해시 검증 실패! (기대: ${expectedHash}, 계산: ${computedHash})`);
  }

  process.stdout.write(`[1] 사본 해시 무결성 검증 완료 (SHA-256: ${computedHash})\n`);

  const policyObj = JSON.parse(rawJson);
  process.stdout.write(`[2] 사본 버전: ${policyObj.version}\n`);
  process.stdout.write(`[3] 사본 정책 규칙: [${policyObj.ruleIds.join(', ')}]\n\n`);

  const currentContent = existsSync(currentPolicyPath) ? readFileSync(currentPolicyPath, 'utf8') : '';
  const backupLines = policyObj.content.split(/\r?\n/);
  const currentLines = currentContent.split(/\r?\n/);

  let diffCount = 0;
  const max = Math.max(backupLines.length, currentLines.length);
  const diffSummary = [];
  for (let i = 0; i < max; i++) {
    if (backupLines[i] !== currentLines[i]) {
      diffCount++;
      if (diffSummary.length < 5) {
        diffSummary.push(`- 줄 ${i + 1}: 사본(${backupLines[i]?.trim() || '없음'}) vs 현재(${currentLines[i]?.trim() || '없음'})`);
      }
    }
  }

  process.stdout.write('--- 현재 정책(src/decider.mjs)과의 차이 분석 ---\n');
  if (diffCount === 0) {
    process.stdout.write('현재 정책이 검증된 안전 사본과 완전히 일치합니다. (차이 없음: 0 라인)\n\n');
  } else {
    process.stdout.write(`총 ${diffCount}개 라인 차이 발견:\n`);
    for (const item of diffSummary) {
      process.stdout.write(`  ${item}\n`);
    }
    process.stdout.write('\n');
  }

  process.stdout.write(`적용 방법: 확인한 버전명을 인자로 전달하여 아래 명령을 실행하세요:\n`);
  process.stdout.write(`  npm run restore:apply -- --confirm=${policyObj.version}\n`);
}

main().catch((err) => {
  process.stderr.write(`[restore:plan 실패] ${err.message}\n`);
  process.exit(1);
});
