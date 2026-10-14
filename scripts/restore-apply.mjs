import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const backupJsonPath = join(root, 'backups', 'step10', 'safe-policy.json');
const backupShaPath = join(root, 'backups', 'step10', 'safe-policy.sha256');
const currentPolicyPath = join(root, 'src', 'decider.mjs');

function parseConfirmArg() {
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('--confirm=')) {
      return arg.slice('--confirm='.length).trim();
    }
  }
  return null;
}

function validatePolicyContent(content) {
  if (typeof content !== 'string' || !content.trim()) {
    throw new Error('정책 사본 내용이 비어 있습니다.');
  }
  if (!content.includes('RULE_IDS') || !content.includes('export async function decide(')) {
    throw new Error('정책 사본에 필수 항목(RULE_IDS 또는 decide 함수)이 누락되었습니다.');
  }
  const secretPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_secret_[A-Za-z0-9_-]{12,}|\bsk-[A-Za-z0-9_-]{20,}/u;
  if (secretPattern.test(content)) {
    throw new Error('정책 사본에 비밀값이 포함되어 있어 검증에 실패했습니다.');
  }
}

async function main() {
  process.stdout.write('=== 10단계 안전 정책 복원 적용 (restore:apply) ===\n\n');

  const confirmVersion = parseConfirmArg();

  if (!existsSync(backupJsonPath) || !existsSync(backupShaPath)) {
    throw new Error('안전 정책 사본 파일(backups/step10/safe-policy.json 또는 .sha256)이 없습니다. 운영 정책을 건드리지 않고 중단합니다.');
  }

  // 1. 1차 검증
  const rawJson = readFileSync(backupJsonPath, 'utf8');
  const expectedHash = readFileSync(backupShaPath, 'utf8').trim().toLowerCase();
  const computedHash = createHash('sha256').update(rawJson, 'utf8').digest('hex');

  const bufExpected = Buffer.from(expectedHash, 'hex');
  const bufComputed = Buffer.from(computedHash, 'hex');

  if (bufExpected.length !== bufComputed.length || !timingSafeEqual(bufExpected, bufComputed)) {
    throw new Error('안전 정책 사본 해시 검증 실패! 위변조가 의심되어 운영 정책을 건드리지 않고 중단합니다.');
  }

  const policyObj = JSON.parse(rawJson);
  validatePolicyContent(policyObj.content);

  if (confirmVersion && confirmVersion !== policyObj.version) {
    throw new Error(`버전 불일치: 지정한 버전(${confirmVersion})이 사본의 버전(${policyObj.version})과 일치하지 않습니다.`);
  }

  process.stdout.write(`[1] 복원 대상 버전 확인: ${policyObj.version}\n`);
  process.stdout.write(`[2] 사본 무결성 해시 확인 완료: ${computedHash}\n\n`);

  // 2. 실행 전 바뀔 항목(Diff) 확인
  const currentContent = existsSync(currentPolicyPath) ? readFileSync(currentPolicyPath, 'utf8') : '';
  const backupLines = (policyObj.content || '').split(/\r?\n/);
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

  process.stdout.write('--- 실행 전 바뀔 항목 확인 ---\n');
  process.stdout.write(`- 대상 파일: src/decider.mjs\n`);
  process.stdout.write(`- 복원 버전: ${policyObj.version}\n`);
  process.stdout.write(`- 보존 대상: Git 커밋/감사 이력, 탐지 모듈(src/detect.mjs), DB 감사 기록\n`);
  process.stdout.write(`- 변경될 라인 수: ${diffCount}개 라인\n`);
  for (const item of diffSummary) {
    process.stdout.write(`  ${item}\n`);
  }
  process.stdout.write('\n');

  // 3. 적용 직전 디스크에서 사본을 다시 읽어 재검토 및 재검증
  process.stdout.write('[3] 적용 직전 재검토: 사본을 디스크에서 다시 읽어 재검증 수행...\n');
  if (!existsSync(backupJsonPath) || !existsSync(backupShaPath)) {
    throw new Error('적용 직전 검토: 백업 파일이 부재하여 운영 정책을 건드리지 않고 중단합니다.');
  }
  const reReadRaw = readFileSync(backupJsonPath, 'utf8');
  const reReadExpHash = readFileSync(backupShaPath, 'utf8').trim().toLowerCase();
  const reReadCompHash = createHash('sha256').update(reReadRaw, 'utf8').digest('hex');
  const bExp = Buffer.from(reReadExpHash, 'hex');
  const bComp = Buffer.from(reReadCompHash, 'hex');
  if (bExp.length !== bComp.length || !timingSafeEqual(bExp, bComp)) {
    throw new Error('적용 직전 재검증 실패: 정책 JSON 사본 해시가 일치하지 않아 운영 정책을 건드리지 않고 중단합니다.');
  }
  const reReadObj = JSON.parse(reReadRaw);
  validatePolicyContent(reReadObj.content);
  process.stdout.write('    재검증 성공: 사본 무결성 및 규칙 계약 확인 완료.\n\n');

  // 4. 정책 사본을 src/decider.mjs에 적용 (기존 감사 기록이나 이력은 온전히 보존)
  writeFileSync(currentPolicyPath, reReadObj.content, 'utf8');
  process.stdout.write('[4] src/decider.mjs에 안전 정책 사본 복원 완료 (감사 기록 및 이력 보존)\n\n');

  // 5. 동작 확인
  const deciderUrl = pathToFileURL(currentPolicyPath);
  const { decide } = await import(`${deciderUrl.href}?t=${Date.now()}`);

  const normalReq = {
    schema: 'aleph.sdp.request.v1',
    requestId: 'restore_test_normal',
    subjectId: 'user_a',
    deviceId: 'dev_a_registered',
    service: 'notes',
    method: 'GET',
    path: '/api/notes/note_1',
    route: '/api/notes/:id',
    deviceRegistered: true,
  };
  const normalRes = await decide(normalReq);

  const forbiddenReq = {
    schema: 'aleph.sdp.request.v1',
    requestId: 'restore_test_forbidden',
    subjectId: 'user_b',
    deviceId: 'dev_b_unregistered',
    service: 'notes',
    method: 'GET',
    path: '/zone2/notes/note_1',
    route: '/zone2/notes/:id',
    deviceRegistered: false,
  };
  const forbiddenRes = await decide(forbiddenReq);

  if (normalRes.decision !== 'allow') {
    throw new Error(`정상 요청이 허용되지 않았습니다: decision=${normalRes.decision}`);
  }
  if (forbiddenRes.decision !== 'deny') {
    throw new Error(`금지 요청이 거부되지 않았습니다: decision=${forbiddenRes.decision}`);
  }

  process.stdout.write('[3] 복원 후 동작 검증 완료 (정상 요청 allow, 미등록/타구역 deny 확인)\n\n');

  // 결과는 artifacts/에만 기록
  mkdirSync(join(root, 'artifacts'), { recursive: true });
  const resultPath = join(root, 'artifacts', 'policy-restore-result.json');
  const resultData = {
    schema: 'aleph.defense.policy_restore.v1',
    appliedAt: new Date().toISOString(),
    version: policyObj.version,
    policyFile: 'src/decider.mjs',
    ruleIds: policyObj.ruleIds,
    sha256: computedHash,
    verification: {
      normalAllow: normalRes.decision === 'allow',
      forbiddenDeny: forbiddenRes.decision === 'deny',
    },
    auditHistoryPreserved: true,
  };
  writeFileSync(resultPath, JSON.stringify(resultData, null, 2) + '\n', 'utf8');
  process.stdout.write(`[4] 복원 결과 기록 완료: artifacts/policy-restore-result.json\n`);
  process.stdout.write('\n[성공] 안전 정책이 성공적으로 복원되고 검증되었습니다.\n');
}

main().catch((err) => {
  process.stderr.write(`[restore:apply 실패] ${err.message}\n`);
  process.exit(1);
});
