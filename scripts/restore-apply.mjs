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

async function main() {
  process.stdout.write('=== 10단계 안전 정책 복원 적용 (restore:apply) ===\n\n');

  const confirmVersion = parseConfirmArg();
  if (!confirmVersion) {
    throw new Error('적용할 버전명을 반드시 지정해야 합니다. 예: npm run restore:apply -- --confirm=<버전>');
  }

  if (!existsSync(backupJsonPath) || !existsSync(backupShaPath)) {
    throw new Error('안전 정책 사본 파일이 없습니다.');
  }

  const rawJson = readFileSync(backupJsonPath, 'utf8');
  const expectedHash = readFileSync(backupShaPath, 'utf8').trim().toLowerCase();
  const computedHash = createHash('sha256').update(rawJson, 'utf8').digest('hex');

  const bufExpected = Buffer.from(expectedHash, 'hex');
  const bufComputed = Buffer.from(computedHash, 'hex');

  if (bufExpected.length !== bufComputed.length || !timingSafeEqual(bufExpected, bufComputed)) {
    throw new Error('안전 정책 사본 해시 검증 실패! 위변조가 의심되어 복원을 중단합니다.');
  }

  const policyObj = JSON.parse(rawJson);

  if (confirmVersion !== policyObj.version) {
    throw new Error(`버전 불일치: 지정한 버전(${confirmVersion})이 사본의 버전(${policyObj.version})과 일치하지 않습니다.`);
  }

  process.stdout.write(`[1] 사본 버전 및 무결성 확인 완료: ${policyObj.version}\n`);

  // 정책 사본을 src/decider.mjs에 적용 (기존 감사 기록이나 이력은 온전히 보존)
  writeFileSync(currentPolicyPath, policyObj.content, 'utf8');
  process.stdout.write('[2] src/decider.mjs에 안전 정책 사본 복원 완료 (감사 기록 및 이력 보존)\n');

  // 동작 확인
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
