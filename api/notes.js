import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

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

  // 화면 코드에서 Supabase 공개 키를 제거하기 위한 서버 로그인 처리 액션
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const isLoginAction = request.method?.toUpperCase() === 'POST' && url.searchParams.get('action') === 'login';

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

  const supabase = createClient(supabaseUrl, supabaseSecretKey);

  // 요청 ID 추출 (Vercel rewrite query 파라미터 또는 URL pathname)
  const pathSegments = url.pathname.split('/').filter(Boolean);
  const pathId = request.query?.id || (pathSegments.length >= 3 ? pathSegments[2] : null);

  // 요청마다 서버가 구별할 수 있는 자원 ID 식별 (기본: 'notes', 공지: 'announcements')
  const resourceParam = url.searchParams.get('resourceId') || url.searchParams.get('resource') || url.searchParams.get('type');
  const isAnnouncement = resourceParam === 'announcements' || resourceParam === 'announcement' || resourceParam === 'notices'
    || url.pathname.includes('announcement') || url.pathname.includes('notice');
  const resourceId = isAnnouncement ? 'announcements' : 'notes';

  response.setHeader('X-Resource-Id', resourceId);

  const method = request.method?.toUpperCase();

  // 본문 파싱 (클라이언트가 보낸 role, owner_id 등 임의 권한 클레임은 절대 신뢰하지 않음)
  let payload = request.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch { payload = {}; }
  }
  payload = payload || {};

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
