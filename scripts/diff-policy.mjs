import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

function git(...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    timeout: 5000,
    windowsHide: true,
  }).trim();
}

// 1. 침해 전 검증된 안전 정책 사본 탐색 및 무결성 검증
function findVerifiedBackup() {
  const backupMjsPath = join(root, 'backup', 'decider.mjs');
  if (existsSync(backupMjsPath)) {
    const content = readFileSync(backupMjsPath, 'utf8');
    return { source: '로컬 백업 파일 (backup/decider.mjs)', version: 'local-backup-mjs', content };
  }

  const backupJsonPath = join(root, 'backups', 'step10', 'safe-policy.json');
  if (existsSync(backupJsonPath)) {
    const raw = readFileSync(backupJsonPath, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      source: '안전 정책 JSON 사본 (backups/step10/safe-policy.json)',
      version: parsed.version || 'v1.0.0-safe-policy',
      content: parsed.content || raw,
    };
  }

  throw new Error('안전 정책 사본(backup/decider.mjs 또는 backups/step10/safe-policy.json)을 찾을 수 없습니다.');
}

// 사본 무결성 및 계약 검증
function validatePolicyContent(content) {
  if (typeof content !== 'string' || !content.trim()) {
    throw new Error('정책 사본 내용이 비어 있습니다.');
  }

  if (!content.includes('RULE_IDS') || !content.includes('export async function decide(')) {
    throw new Error('정책 사본에 필수 항목(RULE_IDS 또는 decide 함수)이 누락되었습니다.');
  }

  // 비밀값 패턴 검사
  const secretPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_secret_[A-Za-z0-9_-]{12,}|\bsk-[A-Za-z0-9_-]{20,}/u;
  if (secretPattern.test(content)) {
    throw new Error('정책 사본에 비밀값이 포함되어 있어 검증에 실패했습니다.');
  }
}

function computeDiff(originalLines, currentLines) {
  const diffs = [];
  const max = Math.max(originalLines.length, currentLines.length);

  for (let i = 0; i < max; i++) {
    const orig = originalLines[i];
    const curr = currentLines[i];
    if (orig !== curr) {
      if (orig !== undefined && curr !== undefined) {
        diffs.push(`! [줄 ${i + 1}]`);
        diffs.push(`  - 복원 사본: ${orig.trim()}`);
        diffs.push(`  + 현재 시험: ${curr.trim()}`);
      } else if (orig !== undefined) {
        diffs.push(`- [줄 ${i + 1}] 복원 사본에만 존재: ${orig.trim()}`);
      } else {
        diffs.push(`+ [줄 ${i + 1}] 현재 시험에만 추가됨: ${curr.trim()}`);
      }
    }
  }
  return diffs;
}

try {
  process.stdout.write('=== 10단계 안전 정책 사본과 현재 시험 정책 차이 확인 ===\n\n');

  // 1. 사본 탐색
  const backup = findVerifiedBackup();
  process.stdout.write(`[1] 사본 위치: ${backup.source}\n`);
  process.stdout.write(`[2] 복원 대상 버전: ${backup.version}\n`);

  // 2. 사본 검증
  validatePolicyContent(backup.content);
  process.stdout.write('[3] 사본 검증 결과: 정상 (RULE_IDS, decide 함수 무결성 확인 및 비밀값 없음)\n\n');

  // 3. 현재 시험 정책 조회 (src/decider.mjs)
  const currentPath = join(root, 'src', 'decider.mjs');
  if (!existsSync(currentPath)) {
    throw new Error('현재 시험 정책 파일(src/decider.mjs)이 존재하지 않습니다.');
  }
  const currentContent = readFileSync(currentPath, 'utf8');

  // 4. 차이점 분석
  const backupLines = backup.content.split(/\r?\n/);
  const currentLines = currentContent.split(/\r?\n/);

  // RULE_IDS 비교
  const backupRuleMatch = backup.content.match(/RULE_IDS\s*=\s*Object\.freeze\(\[(\s*[\s\S]*?)\]\)/);
  const currentRuleMatch = currentContent.match(/RULE_IDS\s*=\s*Object\.freeze\(\[(\s*[\s\S]*?)\]\)/);

  const backupRules = backupRuleMatch ? backupRuleMatch[1].replace(/['"\s]/g, '').split(',').filter(Boolean) : [];
  const currentRules = currentRuleMatch ? currentRuleMatch[1].replace(/['"\s]/g, '').split(',').filter(Boolean) : [];

  process.stdout.write('--- 정책 규칙(RULE_IDS) 비교 ---\n');
  process.stdout.write(`- 복원 사본 규칙: [${backupRules.join(', ')}]\n`);
  process.stdout.write(`- 현재 시험 규칙: [${currentRules.join(', ')}]\n\n`);

  const diffs = computeDiff(backupLines, currentLines);

  process.stdout.write('--- 변경 범위 (Diff 요약) ---\n');
  if (diffs.length === 0) {
    process.stdout.write('안전 정책 사본과 현재 시험 정책 간에 내용 차이가 없습니다. (완전 일치)\n');
  } else {
    process.stdout.write(`총 ${diffs.length}개 차이 발견:\n`);
    for (const line of diffs.slice(0, 30)) {
      process.stdout.write(`${line}\n`);
    }
    if (diffs.length > 30) {
      process.stdout.write(`... 외 ${diffs.length - 30}줄 생략\n`);
    }
  }

  process.stdout.write('\n[안내] 실제 운영 정책 파일은 수정되지 않았습니다. (차이 확인 완료)\n');
} catch (error) {
  process.stderr.write(`[검증 실패 및 중단] ${error.message}\n`);
  process.exit(1);
}
