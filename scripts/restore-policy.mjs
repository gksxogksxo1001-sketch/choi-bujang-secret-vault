import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');

function git(...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    timeout: 5000,
    windowsHide: true,
  }).trim();
}

// 1. 검증된 안전 정책 사본 탐색
function findVerifiedPolicy() {
  const backupPath = join(root, 'backup', 'decider.mjs');
  if (existsSync(backupPath)) {
    const content = readFileSync(backupPath, 'utf8');
    return {
      source: '로컬 백업 파일 (backup/decider.mjs)',
      version: 'local-backup',
      content,
    };
  }

  try {
    const logList = git('log', '--grep=저장점', '--format=%H %s', '-n', '5')
      .split(/\r?\n/)
      .filter(Boolean);

    if (!logList.length) {
      throw new Error('검증된 저장점 커밋을 찾을 수 없습니다.');
    }

    const [latestCheckpoint] = logList;
    const [commitHash, ...subjectParts] = latestCheckpoint.split(' ');
    const commitTitle = subjectParts.join(' ');
    const content = git('show', `${commitHash}:src/decider.mjs`);

    return {
      source: `Git 검증 저장점 (${commitTitle})`,
      version: commitHash.slice(0, 12),
      commitHash,
      content,
    };
  } catch (error) {
    throw new Error(`안전 정책 사본 탐색 실패: ${error.message}`);
  }
}

// 사본 유효성 및 보안 검증
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

async function verifyDeciderBehavior(deciderPath) {
  const deciderUrl = pathToFileURL(deciderPath);
  const { decide, RULE_IDS } = await import(`${deciderUrl.href}?t=${Date.now()}`);

  if (typeof decide !== 'function') {
    throw new Error('복원된 파일에서 decide 함수를 내보내지 않았습니다.');
  }

  // A 정상 요청 테스트: 등록 기기 + 자신의 메모 조회
  const reqA = {
    schema: 'aleph.sdp.request.v1',
    requestId: 'test_a_normal',
    subjectId: 'user_a',
    deviceId: 'dev_a_registered',
    service: 'notes',
    method: 'GET',
    path: '/api/notes/note_a_1',
    route: '/api/notes/:id',
    deviceRegistered: true,
  };
  const resA = await decide(reqA);

  if (resA.decision !== 'allow') {
    throw new Error(`A 정상 요청이 허용되지 않았습니다 (decision: ${resA.decision}, reasonCode: ${resA.reasonCode})`);
  }

  // B의 A 자료(타인 영역/타 구역) 요청 테스트: B가 다른 경로 또는 타인 자원 요청
  const reqB = {
    schema: 'aleph.sdp.request.v1',
    requestId: 'test_b_attack',
    subjectId: 'user_b',
    deviceId: 'dev_b_registered',
    service: 'notes',
    method: 'GET',
    path: '/zone2/notes/note_a_1',
    route: '/zone2/notes/:id',
    deviceRegistered: true,
  };
  const resB = await decide(reqB);

  if (resB.decision !== 'deny') {
    throw new Error(`B의 타 구역/타인 자료 요청이 거부되지 않았습니다 (decision: ${resB.decision})`);
  }
  if (resB.reasonCode !== 'zone_access_denied') {
    throw new Error(`B의 요청 거부 사유 코드가 zone_access_denied가 아닙니다 (현재: ${resB.reasonCode})`);
  }

  return { resA, resB, rules: RULE_IDS };
}

async function main() {
  process.stdout.write('=== 10단계 검증 안전 정책 복원 절차 ===\n\n');

  // 1. 사본 탐색 및 검증
  const verified = findVerifiedPolicy();
  validatePolicyContent(verified.content);

  process.stdout.write(`[1] 복원 대상 정책: ${verified.source}\n`);
  process.stdout.write(`[2] 복원 버전 식별자: ${verified.version}\n\n`);

  // 2. 현재 상태와 비교하여 바뀔 항목 사전 확인
  const targetPath = join(root, 'src', 'decider.mjs');
  const currentContent = existsSync(targetPath) ? readFileSync(targetPath, 'utf8') : '';

  const backupLines = verified.content.split(/\r?\n/);
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
  process.stdout.write(`- 보존 대상: Git 커밋/감사 이력(history), 탐지 모듈(src/detect.mjs), DB 감사 기록\n`);
  process.stdout.write(`- 변경될 라인 수: ${diffCount}개 라인\n`);
  for (const item of diffSummary) {
    process.stdout.write(`  ${item}\n`);
  }
  process.stdout.write('\n');

  // 3. 안전 정책 복원 적용 (기록 파괴 없이 대상 파일만 안전하게 갱신)
  writeFileSync(targetPath, verified.content, 'utf8');
  process.stdout.write('[3] 복원 완료: src/decider.mjs에 검증된 정책 사본이 안전하게 복원되었습니다.\n\n');

  // 4. 복원 후 행위 검증 (A 정상 요청 허용, B의 타 구역/타인 자료 요청 거부)
  process.stdout.write('--- 복원 후 정책 동작 확인 ---\n');
  const verification = await verifyDeciderBehavior(targetPath);
  process.stdout.write(`- 보존된 정책 규칙: [${verification.rules.join(', ')}]\n`);
  process.stdout.write(`- A 정상 요청 (/api/notes/:id): 허용됨 (decision: ${verification.resA.decision})\n`);
  process.stdout.write(`- B 비인가 요청 (/zone2/notes/:id): 거부됨 (decision: ${verification.resB.decision}, reasonCode: ${verification.resB.reasonCode})\n`);

  process.stdout.write('\n[성공] 검증된 안전 정책 복원 및 정상/거부 행위 확인 완료.\n');
}

main().catch((error) => {
  process.stderr.write(`[복원 실패 및 중단] ${error.message}\n`);
  process.exit(1);
});
