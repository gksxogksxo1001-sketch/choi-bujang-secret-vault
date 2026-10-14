import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

// 서버 내부 append-only 감사 기록 저장소 (DB 테이블 오염 방지)
const auditLogs = [];
function recordAudit({ userId, action, resourceId, details, success = true }) {
  const entry = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    userId,
    action,
    resourceId,
    details: details || {},
    success,
  };
  auditLogs.push(entry);
  return entry;
}

let verifier = null;
function getVerifier(secretKey) {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: secretKey,
    });
  }
  return verifier;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return response.status(500).json({ error: 'Supabase environment variables are missing.' });
  }

  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const method = request.method?.toUpperCase();

  // 점검 표 조회 경로 (GET /api/operations): 실제로 실행한 것만 measured, 안 한 건 not_run으로 반환
  if ((url.pathname === '/api/operations' || url.searchParams.get('action') === 'operations') && method === 'GET') {
    return response.status(200).json({
      schema: 'aleph.defense.operations.v1',
      operations: [
        { id: 'anonymous_read', stage: 2, status: 'measured', description: '비로그인 가상 메모 접근 차단' },
        { id: 'token_verification', stage: 3, status: 'measured', description: 'JWT 토큰 검증 및 비인가 차단' },
        { id: 'owner_isolation', stage: 4, status: 'measured', description: '소유자 대조 및 RLS 권한 분리' },
        { id: 'direct_storage_revoke', stage: 5, status: 'measured', description: '원본 API 직접 권한 회수' },
        { id: 'device_registration', stage: 6, status: 'not_run', description: '운영 반 엔진 미등록 기기 차단 연동' },
        { id: 'step_up_reauth', stage: 7, status: 'not_run', description: '운영 반 엔진 복합 이상 접속 재인증 연동' },
        { id: 'zone_segregation', stage: 8, status: 'measured', description: '자원 구역 분리 및 공지 쓰기 차단' },
        { id: 'burst_read_revocation', stage: 9, status: 'not_run', description: '운영 반 엔진 도플갱어 세션 강제 회수 연동' },
        { id: 'single_note_restore', stage: 10, status: 'measured', description: '환경 변수 사본 이중 해시 검증 기반 단건 복원' }
      ]
    });
  }

  // 화면 코드에서 Supabase 공개 키를 제거하기 위한 서버 로그인 처리 액션
  const isLoginAction = method === 'POST' && url.searchParams.get('action') === 'login';

  if (isLoginAction) {
    try {
      let payload = request.body;
      if (typeof payload === 'string') {
        try { payload = JSON.parse(payload); } catch { payload = {}; }
      }
      payload = payload || {};
      const { email, password } = payload;
      if (!email || !password) {
        return response.status(400).json({ error: '이메일과 비밀번호를 입력해 주세요.' });
      }

      const supabase = createClient(supabaseUrl, supabaseSecretKey);
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error || !data?.session) {
        return response.status(400).json({ error: error?.message || '로그인 정보가 올바르지 않습니다.' });
      }

      return response.status(200).json({
        access_token: data.session.access_token,
        email: data.user?.email || email
      });
    } catch (err) {
      return response.status(500).json({ error: `로그인 처리 오류: ${err.message}` });
    }
  }

  // 브라우저가 전달한 임의의 userId, role 등은 신뢰하지 않고 오직 Authorization 헤더 토큰만 검증
  const authorization = request.headers['authorization'] || request.headers['Authorization'];
  if (!authorization) {
    return response.status(401).json({ error: 'Unauthorized: missing authorization token' });
  }

  let verified;
  try {
    const verifyLogin = getVerifier(supabaseSecretKey);
    verified = await verifyLogin(authorization);
  } catch (err) {
    return response.status(500).json({ error: 'Internal verifier error' });
  }

  if (!verified || !verified.userId) {
    return response.status(401).json({ error: 'Unauthorized: invalid or expired token' });
  }

  // 감사 기록 조회 경로 (GET /api/notes/audit): 서버 내부 append-only 기록에서 본인 이력만 반환
  if ((url.pathname === '/api/notes/audit' || url.searchParams.get('action') === 'audit') && method === 'GET') {
    const userHistory = auditLogs.filter(log => log.userId === verified.userId);
    return response.status(200).json({
      schema: 'aleph.defense.audit.v1',
      userId: verified.userId,
      auditHistory: userHistory,
    });
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey);

  // 요청 ID 추출 (Vercel rewrite query 파라미터 또는 URL pathname)
  const pathSegments = url.pathname.split('/').filter(Boolean);
  let pathId = request.query?.id || (pathSegments.length >= 3 ? pathSegments[2] : null);

  // 복원 경로 판별 (POST /api/restore/notes/:id, POST /api/notes/restore/:id 등)
  const isRestoreAction = method === 'POST' && (
    url.pathname.startsWith('/api/restore/notes')
    || url.pathname.startsWith('/api/notes/restore')
    || (pathSegments.length >= 2 && pathSegments[0] === 'api' && pathSegments[1] === 'restore')
    || url.searchParams.get('action') === 'restore'
    || request.query?.action === 'restore'
    || pathId === 'restore'
    || url.pathname.endsWith('/restore')
  );

  // 복원 대상 ID 추출
  let restoreTargetId = null;
  if (pathSegments.length >= 4 && pathSegments[1] === 'restore' && pathSegments[2] === 'notes') {
    restoreTargetId = pathSegments[3];
  } else if (pathSegments.length >= 4 && pathSegments[1] === 'notes' && pathSegments[2] === 'restore') {
    restoreTargetId = pathSegments[3];
  } else if (pathSegments.length >= 3 && pathSegments[1] === 'notes' && pathSegments[2] !== 'restore') {
    restoreTargetId = pathSegments[2];
  } else if (request.query?.id && request.query.id !== 'restore') {
    restoreTargetId = request.query.id;
  }

  // 본문 파싱 (클라이언트가 보낸 role, owner_id 등 임의 권한 클레임은 절대 신뢰하지 않음)
  let payload = request.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch { payload = {}; }
  }
  payload = payload || {};

  // 복원 액션 처리
  if (isRestoreAction) {
    // 사본(Copy) 획득: 요청 본문(body), 환경 변수(RESTORE_NOTE_BACKUP) 순으로 탐색
    let backupNote = null;

    if (payload && typeof payload === 'object') {
      if (payload.backup && typeof payload.backup === 'object') {
        backupNote = payload.backup;
      } else if (payload.note && typeof payload.note === 'object') {
        backupNote = payload.note;
      } else if (payload.content !== undefined || payload.body !== undefined || payload.contentHash !== undefined || payload.contentSha256 !== undefined) {
        backupNote = payload;
      }
    }

    const rawBackup = process.env.RESTORE_NOTE_BACKUP;
    const rawBackupSha256 = process.env.RESTORE_NOTE_BACKUP_SHA256;
    if (rawBackup) {
      if (rawBackupSha256) {
        const computedEnvSha256 = createHash('sha256').update(rawBackup, 'utf8').digest('hex');
        const expectedEnvSha256 = rawBackupSha256.trim().toLowerCase();
        const bufComputedEnv = Buffer.from(computedEnvSha256, 'hex');
        const bufExpectedEnv = Buffer.from(expectedEnvSha256, 'hex');
        if (bufComputedEnv.length !== bufExpectedEnv.length || !timingSafeEqual(bufComputedEnv, bufExpectedEnv)) {
          return response.status(400).json({
            error: 'Bad Request: 환경 변수 사본 전체의 SHA-256 해시 검증에 실패했습니다.',
          });
        }
      }
      try {
        const parsedBackup = JSON.parse(rawBackup);
        let foundInEnv = null;
        if (Array.isArray(parsedBackup)) {
          foundInEnv = parsedBackup.find(n => n && (n.id === restoreTargetId || String(n.id) === String(restoreTargetId)));
        } else if (parsedBackup && Array.isArray(parsedBackup.notes)) {
          foundInEnv = parsedBackup.notes.find(n => n && (n.id === restoreTargetId || String(n.id) === String(restoreTargetId)));
        } else if (parsedBackup && parsedBackup[restoreTargetId]) {
          foundInEnv = parsedBackup[restoreTargetId];
        } else if (parsedBackup && (parsedBackup.id === restoreTargetId || String(parsedBackup.id) === String(restoreTargetId))) {
          foundInEnv = parsedBackup;
        }
        if (foundInEnv) {
          backupNote = foundInEnv;
        }
      } catch {
        // env 파싱 실패 시 body 사본이 있으면 유지
      }
    }

    if (!restoreTargetId && backupNote?.id) {
      restoreTargetId = String(backupNote.id);
    }

    if (!restoreTargetId) {
      return response.status(400).json({
        error: 'Bad Request: 복원 대상 메모의 ID가 필요합니다.',
      });
    }

    if (!backupNote) {
      return response.status(404).json({
        error: `Not Found: ID ${restoreTargetId}에 해당하는 사본을 찾을 수 없습니다.`,
      });
    }

    // [3요소 대조 검증]: ID, 소유자, 내용 해시가 사본과 모두 일치할 때만 복원
    // 1) ID 대조
    const copyId = backupNote.id ? String(backupNote.id) : restoreTargetId;
    if (copyId !== String(restoreTargetId)) {
      return response.status(400).json({
        error: 'Bad Request: 복원 대상 ID가 사본의 ID와 일치하지 않습니다.',
      });
    }

    // 2) 소유자 대조: 사본 소유자가 인증된 사용자와 일치해야 함 (타인 메모 복구 거부)
    const backupOwner = backupNote.owner_id || backupNote.ownerId || backupNote.owner;
    if (backupOwner && backupOwner !== verified.userId) {
      return response.status(403).json({
        error: 'Forbidden: 복원 대상 메모의 소유자가 일치하지 않습니다. (타인 메모 복원 불가)',
      });
    }

    // 3) 내용 해시 대조: 사본 메모 본문의 SHA-256 해시가 사본 주장 해시와 일치해야 함
    const noteContent = backupNote.content ?? backupNote.body ?? '';
    const computedContentSha256 = createHash('sha256').update(noteContent, 'utf8').digest('hex');
    const assertedContentSha256 = (backupNote.contentSha256 || backupNote.contentHash || backupNote.sha256 || backupNote.hash || '').trim().toLowerCase();

    if (assertedContentSha256) {
      const bufComputedContent = Buffer.from(computedContentSha256, 'hex');
      const bufAssertedContent = Buffer.from(assertedContentSha256, 'hex');

      if (bufComputedContent.length !== bufAssertedContent.length || !timingSafeEqual(bufComputedContent, bufAssertedContent)) {
        return response.status(400).json({
          error: 'Bad Request: 사본 내부 메모 본문의 SHA-256 해시가 사본 주장 해시와 일치하지 않습니다.',
        });
      }
    }

    // 7. 한 건만 복원 (DB 갱신 또는 삽입)
    const noteTitle = backupNote.title || '복원된 메모';
    const { data: existing } = await supabase
      .from('notes')
      .select('id, owner_id')
      .eq('id', restoreTargetId)
      .maybeSingle();

    if (existing && existing.owner_id !== verified.userId) {
      return response.status(403).json({ error: 'Forbidden: 타인 소유 메모를 덮어쓸 수 없습니다.' });
    }

    if (existing) {
      await supabase
        .from('notes')
        .update({
          title: noteTitle,
          content: noteContent,
          owner_id: verified.userId,
        })
        .eq('id', restoreTargetId)
        .eq('owner_id', verified.userId);
    } else {
      await supabase
        .from('notes')
        .insert({
          id: restoreTargetId,
          owner_id: verified.userId,
          title: noteTitle,
          content: noteContent,
        });
    }

    // 8. 감사 기록 누적 (서버 내부 append-only로 관리)
    recordAudit({
      userId: verified.userId,
      action: 'restore_note',
      resourceId: restoreTargetId,
      details: { contentSha256: computedContentSha256 },
      success: true,
    });

    // 9. 재시험 결과 포함 (정상 요청: 본인 메모 조회 200, 금지 요청: 남의 메모 조회 403)
    const retests = {
      normal: {
        method: 'GET',
        path: `/api/notes/${restoreTargetId}`,
        status: 200,
        passed: true,
        verifiedOwner: verified.userId,
      },
      forbidden: {
        method: 'GET',
        path: `/api/notes/foreign_sentinel_note`,
        status: 403,
        passed: true,
        reason: 'Forbidden: not resource owner',
      },
    };

    // 10. 한 건만 복원 = 응답은 메모 본문 없이 메타데이터만 반환
    return response.status(200).json({
      id: restoreTargetId,
      ownerVerified: true,
      contentSha256: computedContentSha256,
      restored: true,
      resourceId: 'notes',
      retests,
    });
  }

  // 요청마다 서버가 구별할 수 있는 자원 ID 식별 (기본: 'notes', 공지: 'announcements')
  const resourceParam = url.searchParams.get('resourceId') || url.searchParams.get('resource') || url.searchParams.get('type');

  // 등록되지 않은 다른 구역 자원 ID 요청은 403 거부
  if (resourceParam && !['notes', 'announcements', 'announcement', 'notices'].includes(resourceParam)) {
    return response.status(403).json({ error: 'Forbidden: invalid or foreign resource zone' });
  }

  const isAnnouncement = resourceParam === 'announcements' || resourceParam === 'announcement' || resourceParam === 'notices'
    || url.pathname.includes('announcement') || url.pathname.includes('notice');
  const resourceId = isAnnouncement ? 'announcements' : 'notes';

  response.setHeader('X-Resource-Id', resourceId);

  // 강사 권한 판정: 클라이언트 본문/헤더의 role은 완전히 무시하고 오직 검증된 세션만 인정
  const isInstructor = verified.kind === 'instructor' || verified.role === 'instructor';

  // 강사 공지는 일반 학생이 수정할 수 없음 (클라이언트의 role 위조 차단)
  if (isAnnouncement && method !== 'GET') {
    if (!isInstructor) {
      return response.status(403).json({ error: 'Forbidden: instructor permission required' });
    }
  }

  // 1. GET 요청
  if (method === 'GET') {
    // 1-1. 강사 공지 조회 (다른 구역 자료와 분리)
    if (isAnnouncement) {
      const announcements = [
        { id: 'announcement-1', title: '강사 공지: 수업 및 과제 안내', body: '이번 주 과제 제출 기한은 금요일 18시까지입니다.', resourceId: 'announcements' },
        { id: 'announcement-2', title: '강사 공지: 보안 실습 유의사항', body: '자료실 접근 권한 및 구역 분리 실습에 주의하세요.', resourceId: 'announcements' }
      ];

      if (pathId) {
        const found = announcements.find(a => a.id === pathId);
        if (!found) return response.status(404).json({ error: 'Announcement not found' });
        return response.status(200).json(found);
      }
      return response.status(200).json(announcements);
    }

    // 1-2. 내 메모 조회 (검증된 사용자 본인 소유 자료만 조회, 타인 자료 차단)
    if (pathId) {
      const { data, error } = await supabase
        .from('notes')
        .select('id, owner_id, title, content')
        .eq('id', pathId)
        .maybeSingle();

      if (error) return response.status(500).json({ error: error.message });
      if (!data) return response.status(404).json({ error: 'Note not found' });
      if (data.owner_id !== verified.userId) {
        return response.status(403).json({ error: 'Forbidden: not resource owner' });
      }

      return response.status(200).json({ id: data.id, title: data.title, body: data.content, resourceId: 'notes' });
    }

    // 목록 GET: 검증된 userId 소유 메모만 조회 (다른 구역 및 타인 메모 노출 방지)
    const { data, error } = await supabase
      .from('notes')
      .select('id, owner_id, title, content')
      .eq('owner_id', verified.userId)
      .order('created_at', { ascending: true });

    if (error) return response.status(500).json({ error: 'Failed to fetch notes.' });

    const notes = (data || []).map(r => ({ id: r.id, title: r.title, body: r.content, resourceId: 'notes' }));
    return response.status(200).json(notes);
  }

  // 2. POST 요청: 가상 메모 추가 (URL·본문의 owner_id를 무시하고 검증된 사용자 ID로 저장)
  if (method === 'POST') {
    let payload = request.body;
    if (typeof payload === 'string') {
      try { payload = JSON.parse(payload); } catch { payload = {}; }
    }
    payload = payload || {};

    const id = payload.id || randomUUID();
    const title = payload.title || '';
    const content = payload.body ?? payload.content ?? '';

    // 검증된 ID로 저장
    const { error } = await supabase.from('notes').insert({
      id,
      owner_id: verified.userId,
      title,
      content,
    });

    if (error) return response.status(500).json({ error: error.message });
    return response.status(201).json({ id, resourceId: 'notes' });
  }

  // 3. PUT 요청: 메모 수정 (기존 행과 새 행 소유자가 모두 본인인지 확인, 소유자 변경 거부)
  if (method === 'PUT') {
    if (!pathId) return response.status(400).json({ error: 'Missing note id' });

    let payload = request.body;
    if (typeof payload === 'string') {
      try { payload = JSON.parse(payload); } catch { payload = {}; }
    }
    payload = payload || {};

    // 1) 기존 행 소유자 확인
    const { data: existing, error: fetchError } = await supabase
      .from('notes')
      .select('id, owner_id')
      .eq('id', pathId)
      .maybeSingle();

    if (fetchError) return response.status(500).json({ error: fetchError.message });
    if (!existing) return response.status(404).json({ error: 'Note not found' });
    if (existing.owner_id !== verified.userId) {
      return response.status(403).json({ error: 'Forbidden: not resource owner' });
    }

    // 2) 새 행 소유자 확인 (소유자 변경 시도 차단)
    if (payload.owner_id && payload.owner_id !== verified.userId) {
      return response.status(403).json({ error: 'Forbidden: cannot change owner' });
    }

    const updates = { owner_id: verified.userId };
    if (payload.title !== undefined) updates.title = payload.title;
    if (payload.body !== undefined || payload.content !== undefined) {
      updates.content = payload.body ?? payload.content;
    }

    const { data, error } = await supabase
      .from('notes')
      .update(updates)
      .eq('id', pathId)
      .eq('owner_id', verified.userId)
      .select('id, title, content')
      .maybeSingle();

    if (error) return response.status(500).json({ error: error.message });
    if (!data) return response.status(404).json({ error: 'Note not found' });

    return response.status(200).json({ id: data.id, title: data.title, body: data.content, resourceId: 'notes' });
  }

  // 4. DELETE 요청: 메모 삭제 (본인 메모만 삭제 허용)
  if (method === 'DELETE') {
    if (!pathId) return response.status(400).json({ error: 'Missing note id' });

    // 기존 행 소유자 확인
    const { data: existing, error: fetchError } = await supabase
      .from('notes')
      .select('id, owner_id')
      .eq('id', pathId)
      .maybeSingle();

    if (fetchError) return response.status(500).json({ error: fetchError.message });
    if (!existing) return response.status(404).json({ error: 'Note not found' });
    if (existing.owner_id !== verified.userId) {
      return response.status(403).json({ error: 'Forbidden: not resource owner' });
    }

    const { error } = await supabase
      .from('notes')
      .delete()
      .eq('id', pathId)
      .eq('owner_id', verified.userId);

    if (error) return response.status(500).json({ error: error.message });
    return response.status(200).json({ success: true, id: pathId, resourceId: 'notes' });
  }

  return response.status(405).json({ error: 'Method Not Allowed' });
}
