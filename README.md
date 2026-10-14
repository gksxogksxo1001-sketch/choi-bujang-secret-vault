# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 가상 메모 문장 검증 및 보안 상태

### 1. GitHub 최신 커밋 & 배포 파일 검증 절차
현재 저장소의 최신 HEAD 커밋과 Vercel 배포 파일에서 가상 메모 문장이 제거되었는지 아래 방법으로 검색해 확인합니다:
- **GitHub HEAD 커밋 검증**:
  ```bash
  git grep "실습용 가상" HEAD
  ```
  *(검색 결과: `schema.sql` 외의 정적 파일 `data.json` 및 `public/data.json`에서 메모 문장이 발견되지 않아야 함)*
- **Vercel 정적 배포 파일 검증**:
  - `https://<your-vercel-app>/data.json` 요청 시 가상 메모 문장이 포함되지 않음(빈 배열 `[]` 또는 `404 Not Found`).

### 2. 과거 노출 및 남은 약점 기록
- **과거 노출 미해소 안내**: 1단계 커밋 이력(Git history) 및 Vercel의 과거 배포 링크(Previous deployments)에는 과거에 작성된 가상 메모 문장이 남아 있으므로, 과거 노출 자체가 완전히 삭제되어 해소된 것은 아닙니다.

## 5단계 현재 작동 기능 및 다시 실행 방법

### 현재 작동하는 기능
1. **서버 함수 단일 진입점 구성**:
   - 브라우저의 메모 읽기·추가·수정·삭제는 Supabase를 직접 호출하지 않고 오직 Vercel 서버 함수(`/api/notes`, `/api/notes/:id`)를 통해서만 수행됩니다.
   - 서버 함수는 `SUPABASE_SECRET_KEY`(`service_role` 키)를 사용하여 안전하게 DB와 통신합니다.
2. **저장소 직접 접근 권한 전면 차단**:
   - `public.notes` 테이블의 `PUBLIC`, `anon`, `authenticated` 직접 권한을 모두 회수(`REVOKE ALL`)하여, 브라우저 토큰이나 공개 anon 키로 Supabase PostgREST Data API에 직접 접근하는 경로를 차단했습니다.
3. **API 레벨 소유자 검증 및 RLS 유지**:
   - 로그인 토큰의 `userId`와 DB의 `owner_id`를 대조하여 본인 메모만 CRUD가 가능하며, 타인 메모 접근 및 소유권 변경 시도는 403 Forbidden으로 거부됩니다.
4. **설정 및 보안 헤더**:
   - `aleph.config.json`에 원본 자료 HTTPS 경로(`originalApiUrl`) 및 `allowedRoutes`가 등록되어 있습니다.
   - `vercel.json`에 `X-Content-Type-Options: nosniff` 보안 헤더가 설정되어 있습니다.
5. **화면 코드 공개 키 제거 (100점 가점)**:
   - 화면 코드(`public/index.html`)에서 `sb_publishable_...` 공개 키와 Supabase 클라이언트를 완전히 제거하고, 로그인까지 Vercel 서버 함수(`POST /api/notes?action=login`)를 통해 처리하도록 개선했습니다.

### 다시 실행하는 방법
1. **로컬 빌드 및 패키지 검사**:
   ```bash
   npm run build -- --local
   npm run test:package
   ```
2. **제출 묶음 생성 및 자기 점검**:
   ```bash
   npm run bundle
   ```
3. **배포 환경 확인**:
   - Vercel 배포 웹 화면에서 로그인 후 A의 메모 읽기, 추가, 수정, 삭제가 정상 수행되는지 확인합니다.
   - 원본 주소(`https://kanrdiuonebmjgfkzubq.supabase.co/rest/v1/notes`)로 직접 요청 시 차단되는지 확인합니다.

## 6단계 기기 등록 판정기 기능 및 확인 순서

### 판정기 구현 내용 (`src/decider.mjs`)
- **규칙 ID (`RULE_IDS`)**: `device_registered`
- **판정 로직**:
  - `request.deviceRegistered === true`: `decision: 'allow'`, `reasonCode: 'approved'`, `ruleIds: ['device_registered']`
  - 미등록(`false`) 또는 값 부재: `decision: 'deny'`, `reasonCode: 'device_not_registered'`, `ruleIds: ['device_registered']`

### 확인 순서
1. 이번 과정에는 따로 설치할 접속 프로그램이 없으므로, 터미널에서 로컬 가상 요청 시험을 실행합니다:
   ```bash
   npm run decider:test
   ```
2. 시험 출력에서 아래 두 항목이 모두 정상적으로 통과하는지 확인합니다:
   - `통과 · 등록 기기의 정상 요청`: 등록 상태(`deviceRegistered: true`)일 때 `decision: 'allow'`, `reasonCode: 'approved'`로 판정
   - `통과 · 미등록 기기의 가상 요청`: 미등록 상태(`deviceRegistered: false`)일 때 `decision: 'deny'`, `reasonCode: 'device_not_registered'`로 거부
3. 미등록 기기 차단 및 공격 검증은 실제 환경에서 심판이 맡아 수행합니다.

*(참고: `npm run decider:test`는 가상 요청 연습이며 실제 심판 판정 통과 증거가 아닙니다.)*

## 7단계 복합 이상 접속 추가 확인(step_up) 기능 및 다시 실행 방법

### 현재 작동하는 기능
1. **가상 접속 신호 및 사건 출처 검증**:
   - `request.signals`의 출처(`judge_fixture`)를 검증하며, 누락되거나 불명확한 접속 정보를 임의의 기본 정상값으로 보정(승격)하지 않습니다.
2. **복합 이상 접속 탐지 및 추가 확인 요구 (`step_up_required`)**:
   - 지역 단독 영구 차단을 지양하고, 평소와 다른 시각, 처음 보는 네트워크, 대량 자료 조회의 복합 이상 징후를 감지합니다.
   - 추가 본인 확인 미완료 시 `decision: 'step_up'`, `reasonCode: 'step_up_required'`로 재인증을 요구합니다.
3. **재인증 완료 후 요청 허용**:
   - `request.stepUp.verified === true` 및 유효 시간(0~900초) 내 요청은 `allow`로 정상 허용합니다.
4. **기존 기기 등록 규칙 유지**:
   - 미등록 기기(`deviceRegistered !== true`)는 즉시 `deny` / `device_not_registered`로 차단합니다.

### 다시 실행하는 방법
```bash
npm run fixture:7
npm run decider:test
```
- `npm run fixture:7`: 정상 사건은 `allow`, 복합 이상 사건은 `step_up`으로 판정되는지 확인합니다.
- `npm run decider:test`: 등록 기기 정상 요청, 미등록 기기 차단, 복합 이상 접속(`step_up`), 재확인 후 허용(`allow`) 4개 항목을 검증합니다.
*(참고: 로컬 가상 사건 연습이며 실제 심판 판정 통과 증거가 아닙니다.)*

## 8단계 자원 구역 분리 및 권한 대조 기능 및 다시 실행 방법

### 현재 작동하는 기능
1. **자료실 메모와 강사 공지 자원 ID 분리 (`api/notes.js`)**:
   - 요청마다 서버가 자원 ID(`notes` vs `announcements`)를 구별하고 응답 헤더(`X-Resource-Id`) 및 본문에 자원 ID를 표시합니다.
   - 강사 공지는 읽기 전용 구역으로 분리되어 일반 학생의 수정·삭제 요청은 거부됩니다.
2. **판정기 구역 규칙 (`zone_segregation`, `src/decider.mjs`)**:
   - 사용자·기기·메서드·정확한 경로를 검증하여 A 자기 메모는 허용하고, B의 A 메모 접근(`zone_access_denied`) 및 일반 학생의 공지 수정(`announcement_readonly`), 알 수 없는 기능 경로(`export` 등, `unknown_route`)를 거부합니다.
3. **자료 API 소유자 및 권한 재검증**:
   - 클라이언트 본문이나 메뉴의 `role`을 신뢰하지 않고, JWT 검증 주체(`userId`)와 DB의 `owner_id`를 대조하여 메뉴 우회 직접 요청 시에도 타인 메모 접근을 차단(`403 Forbidden: not resource owner`)합니다.

### 다시 실행하는 방법
```bash
npm run test:package
npm run decider:test
```
- `npm run test:package`: 패키징 함수 기준표 및 정합성을 검증합니다.
- `npm run decider:test`: 구역 분리 규칙을 포함한 판정기 테스트를 통과하는지 확인합니다.

## 9단계 도플갱어 탐지 및 권한 회수 제안 기능 및 다시 실행 방법

### 현재 작동하는 기능
1. **정제된 판정기 입력 (`src/decider.mjs`)**:
   - 가상 사건에서 가명 사용자, 기기, 요청 종류, 판정 신호만 안전하게 읽고 메모 본문·토큰·실명은 철저히 배제합니다.
   - 복합 의심 탐지(`network === 'unusual'`과 다량 조회 결합)를 유지하고, 지역 단독 판정은 배제합니다.
2. **도플갱어 다량 조회 탐지 및 회수 제안 모듈 (`src/detect.mjs`)**:
   - 10분(600,000ms) 구간 내 동일 `identity.sub`의 GET 요청이 120건을 초과(121건 이상)할 때 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }`를 반환합니다.
   - 120건 이하이거나 분산된 정상 조회 시 `{ action: 'observe' }`를 반환하여 정상 사용자의 접속을 보존합니다.
   - 기존 접속 허용/거부 응답(`decider.mjs`)은 손상시키지 않고 별도 결과로 도출합니다.

### 다시 실행하는 방법
```bash
npm run detect:test
npm run decider:test
```
- `npm run detect:test`: 10분 구간 내 정상/폭주 조회, 사용자별 집계 분리, 시간 분산 조회의 탐지 결과를 검증합니다.
*(참고: 로컬 가상 사건 연습이며 실제 운영 엔진 전달이나 심판 통과 증거가 아닙니다.)*

## 보너스 xdr-01 (무차별 대입 탐지 및 대응) 현재 작동 기능 및 다시 실행 방법

### 현재 작동하는 기능
1. **무차별 대입 공격 패턴 정의 (`xdr/brute-force/patterns.json`)**:
   - MITRE ATT&CK T1110 기반 패턴 정의(단일 주소 고빈도 실패, 다수 계정 대상 스프레이, 성공 없는 대량 실패 지속).
2. **경보 자동 판정 모듈 (`xdr/brute-force/decide.mjs`)**:
   - Wazuh 형태의 보안 경보를 분석하여 세 가지 조치(`block`, `alert`, `record`) 및 신뢰도(0.0~1.0), 판정 사유를 반환.
   - 외부 I/O 없이 순수 자체 로직으로 격리 환경에서 실행 가능.
3. **대응 및 차단 연계 모듈 (`xdr/brute-force/respond.mjs`)**:
   - 판정 결과 중 차단 대상(`block`)을 추출하여 ZTNA 거부 규칙 형식으로 변환하고, 경보 및 차단 이력을 `xdr/alerts.log`에 기록.
4. **XDR 실행 및 결과 생성 (`xdr/brute-force/result.json`)**:
   - `brute-force.json` 픽스처(경보 28건) 대상 판정 수행 및 결과 파일 생성 (block: 10건, alert: 9건, record: 9건).

### 다시 실행하는 방법
```bash
npm run xdr:run -- brute-force
```
- 실행 후 `xdr/brute-force/result.json`에서 판정 건수(`counts`)와 판정 목록(`decisions`)을 확인합니다.

## 보너스 xdr-02 (웹 주입 공격 탐지 및 대응) 현재 작동 기능 및 다시 실행 방법

### 현재 작동하는 기능
1. **웹 주입 공격 패턴 정의 (`xdr/web-injection/patterns.json`)**:
   - MITRE ATT&CK T1190 기반 패턴 정의(SQL 구문 반복 주입, 스크립트 태그 삽입 반복, 상위 디렉터리 경로 순회 반복).
2. **경보 자동 판정 모듈 (`xdr/web-injection/decide.mjs`)**:
   - Wazuh 형태의 웹 경보를 심판 격리 환경 규칙(import 및 파일 I/O 배제)에 맞춰 순수 자체 계산으로 block·alert·record 판정.
   - 확신도 0.95(block, 8건), 0.65(alert, 9건), 0.1(record, 9건) 산출.
3. **대응 및 차단 연계 모듈 (`xdr/web-injection/respond.mjs`)**:
   - 판정 결과 중 차단 대상(`block`) 8건만 ZTNA 거부 규칙으로 변환(만료 시각 및 근거 경보 번호 부착), 알림은 `xdr/alerts.log`에 안전하게 누적.
4. **XDR 실행 및 결과 생성 (`xdr/web-injection/result.json`)**:
   - `web-injection.json` 픽스처(경보 26건) 대상 판정 수행 및 결과 파일 생성 (block: 8건, alert: 9건, record: 9건).

### 다시 실행하는 방법
```bash
npm run xdr:run -- web-injection
```
- 실행 후 `xdr/web-injection/result.json`에서 판정 건수(`counts`)와 판정 목록(`decisions`)을 확인합니다.

## 비공개 가상 메모 단건 안전 복원 (10단계 사본 복구 및 3요소 대조)

### 서비스 및 복원 경로 계약
- **서비스 (Service)**: `notes` (가상 자료실 메모 서비스)
- **주 복원 경로 (Primary Restore Route)**: `POST /api/restore/notes/:id` (동일 기능 별칭: `POST /api/notes/restore/:id`)
- **감사 기록 경로 (Audit Route)**: `GET /api/notes/audit` (서버 내부 append-only 이력 중 본인 기록만 반환)
- **점검 표 경로 (Operations Route)**: `GET /api/operations` (실제 실행 항목은 `measured`, 미실행은 `not_run`으로 정직하게 반환)
- **설정 등록 (`aleph.config.json`)**: `"restoreRoute": "POST /api/restore/notes/:id"`

### ID·소유자·내용 해시 3요소 대조 및 엄격한 상태 코드 계약
복구 대상 한 건의 **ID, 소유자, 내용 해시** 세 값이 사본과 모두 일치할 때만 복원하고 다른 메모는 그대로 보존합니다:
1. **사본 수신 및 탐색 지원**:
   - 요청 본문(`payload.backup`, `payload.note` 또는 직접 본문) 및 환경 변수(`RESTORE_NOTE_BACKUP`, `RESTORE_NOTE_BACKUP_SHA256`)를 모두 지원합니다.
2. **3요소 대조 검증 (`crypto.timingSafeEqual`)**:
   - **ID 대조**: 복구 대상 한 건의 ID가 사본의 ID와 일치해야 합니다. (불일치 시 `400 Bad Request`)
   - **소유자 대조**: 사본의 소유자(`owner_id`)가 서버가 검증한 본인 로그인 토큰(`verified.userId`)과 일치해야 합니다. 타인 메모 복원 시도시 `403 Forbidden`으로 거부됩니다.
   - **내용 해시 대조**: 사본 안의 메모 본문 SHA-256 해시가 사본이 주장하는 해시와 일치하는지 `crypto.timingSafeEqual`로 검증합니다. 위변조 시 `400 Bad Request`로 거부됩니다.
3. **엄격한 상태 코드 판정**:
   - `400 Bad Request`: 대상 ID 또는 내용 해시가 사본과 불일치하는 경우.
   - `401 Unauthorized`: 유효한 로그인 토큰이 없는 경우.
   - `403 Forbidden`: 사본 소유자가 로그인 사용자와 다르거나 타인 소유 메모를 침범하는 경우.
   - `404 Not Found`: 사본 내에 요청한 메모가 존재하지 않는 경우.
   - `200 OK`: 3요소가 모두 일치하여 단건 복원이 성공한 경우.
4. **응답 메타데이터 및 재시험 결과 증거 (`restore.retests`)**:
   - 응답에는 메모 본문을 노출하지 않고 메타데이터(`{ id, ownerVerified: true, contentSha256, restored: true, resourceId: 'notes', retests }`)만 반환합니다.
   - 복원 직후 본인 메모 조회(정상 200)와 타인 메모 조회(금지 403)를 실제로 실행하여 그 증거를 `retests`에 담습니다.
5. **감사 기록 보존**:
   - DB 테이블 오염을 방지하기 위해 서버 내부 append-only 구조로 기록을 누적하며, 복원 작업 자체도 감사 이력으로 남깁니다. `GET /api/notes/audit`으로 본인 이력을 확인합니다.

### 10단계 안전 정책 사본 복원 절차
- **사본 보관**: `backups/step10/safe-policy.json` (및 `.sha256`) 및 `backup/decider.mjs` (커밋 대상).
- **검증 실패 시 중단 원칙**:
  - 사본이 없거나 검증(해시, 필수 함수, 비밀값 패턴)이 실패하면 즉시 중단하며 실제 운영 정책(`src/decider.mjs`)은 건드리지 않습니다.
- **실행 전 사전 확인**:
  - 복원 실행 전에 버전과 현재 정책과의 바뀔 항목(Diff 요약 및 라인 수)을 화면에 보여 줍니다.
- **적용 직전 재검토·재검증**:
  - 디스크에서 사본을 다시 읽어 무결성을 재검증한 후 안전하게 복원을 수행합니다.
- **복원 실행 명령**:
  ```bash
  npm run policy:restore
  # 또는
  npm run restore:apply
  ```
  - 복원 후 A 정상 요청(allow) 및 타 구역/타인 자료 비인가 요청(deny) 동작을 자동으로 확인하며, 기존 감사 기록과 탐지 모듈은 그대로 보존됩니다.

## 복구 후 1~9단계 정상·금지 요청 재실행 순서 및 검증표

가상 메모 사본 복원 및 안전 정책 복원 후, 침해 이전과 동일하게 자료와 정책이 정상 상태로 돌아오고 이전에 차단하던 비인가 요청들이 다시 정상 거부되는지 확인하는 재실행 순서입니다.
실제로 로컬에서 실행 가능한 시험과 외부 심판/운영 반 엔진 전용 미실행 항목을 명확히 구분하여 결과를 꾸미지 않고 기록했습니다.

### 1. 단계별 재실행 순서

#### [1단계 & 2단계] 정적 가상 메모 노출 차단 확인
- **정상 요청 (배포 검사)**: 정적 빌드 결과물 및 배포 상태 확인
  - 실행: `npm run build -- --local`
  - 정상 결과: `public/aleph.json`이 로컬 메타데이터로 정상 생성됨.
- **금지 요청 (공개 노출 차단)**: 비로그인 상태에서 정적 가상 메모 직접 조회 시도
  - 확인 경로: `GET /data.json`
  - 거부 결과: 과거 노출되던 가상 메모 4건이 제거되어 빈 배열(`[]`) 또는 `404 Not Found` 반환.

#### [3단계] 비인증 접근 차단 및 토큰 검증
- **정상 요청 (허용)**: 로그인 후 유효한 `Authorization: Bearer <token>` 헤더를 포함한 메모 목록 조회
  - 확인 경로: `GET /api/notes`
  - 정상 결과: `HTTP 200 OK` 및 본인 메모 목록 반환.
- **금지 요청 (거부)**: 토큰이 없거나 만료/변조된 비로그인 직접 요청
  - 확인 경로: `GET /api/notes` (헤더 없음)
  - 거부 결과: `HTTP 401 Unauthorized` (`Unauthorized: missing authorization token`).

#### [4단계] 자료 API 소유자 격리 및 RLS 권한 확인
- **정상 요청 (허용)**: 시험 계정 B 로그인 후 본인 메모(`B의 가상 메모`) 단건 조회/수정
  - 확인 경로: `GET /api/notes/:id_of_b`
  - 정상 결과: `HTTP 200 OK` 및 본인 메모 내용 정상 조회.
- **금지 요청 (거부)**: 시험 계정 B의 토큰으로 계정 A의 메모 단건 조회 또는 수정/삭제 시도
  - 확인 경로: `GET /api/notes/:id_of_a` (B의 토큰 사용)
  - 거부 결과: `HTTP 403 Forbidden` (`Forbidden: not resource owner`).

#### [5단계] 원본 저장소 직접 접근 전면 차단
- **정상 요청 (허용)**: Vercel 서버 함수 단일 진입점(`/api/notes`)을 통한 안전한 DB 통신
  - 확인 경로: 배포 웹 UI에서 메모 CRUD 수행
  - 정상 결과: 서버 함수가 `service_role` 키로 DB와 정상 통신하여 기능 수행 완료.
- **금지 요청 (거부)**: 브라우저 토큰이나 공개 anon 키로 Supabase 원본 PostgREST API 직접 호출
  - 확인 경로: `GET https://kanrdiuonebmjgfkzubq.supabase.co/rest/v1/notes`
  - 거부 결과: 직접 권한 전면 회수(`REVOKE ALL`)로 인해 `HTTP 401/403` 또는 빈 응답으로 전면 차단.

#### [6단계] 기기 등록 판정기 검증
- **정상 요청 (허용)**: 등록 기기(`deviceRegistered: true`)의 요청
  - 판정 결과: `decision: 'allow'`, `reasonCode: 'approved'`, `ruleIds: ['device_registered']`.
- **금지 요청 (거부)**: 미등록 기기(`deviceRegistered: false` 또는 부재)의 요청
  - 판정 결과: `decision: 'deny'`, `reasonCode: 'device_not_registered'`, `ruleIds: ['device_registered']`.
- **실행 및 상태**:
  - 실행 명령: `npm run decider:test`
  - 상태: **로컬 가상 요청 시험 통과 완료** (운영 반 엔진의 실제 미등록 기기 차단 연동은 **미실행 · 심판 검증 항목**).

#### [7단계] 복합 이상 접속 추가 확인(step_up) 검증
- **정상 요청 (허용)**: 추가 확인 완료 상태(`stepUp.verified === true`, 900초 이내)의 요청
  - 판정 결과: `decision: 'allow'`, `ruleIds: ['step_up_required']`.
- **금지/지연 요청 (재인증 요구)**: 비정상 네트워크(`signals.network === 'unusual'`) + 10건 이상 다량 조회의 복합 의심 요청
  - 판정 결과: `decision: 'step_up'`, `reasonCode: 'step_up_required'`, `ruleIds: ['step_up_required']`.
- **실행 및 상태**:
  - 실행 명령: `npm run fixture:7` 및 `npm run decider:test`
  - 상태: **로컬 가상 픽스처 시험 통과 완료** (운영 엔진의 실제 재인증 흐름 연동은 **미실행 · 계약 준비 전**).

#### [8단계] 구역 분리 및 비허용 경로 차단 검증
- **정상 요청 (허용)**:
  - 본인 단건 메모 읽기/수정: `GET /api/notes/:id` -> `HTTP 200` / `allow`.
  - 강사 공지 읽기: `GET /api/notes?resourceId=announcements` -> `HTTP 200` (`resourceId: 'announcements'`).
- **금지 요청 (거부)**:
  - 타 구역 접두어(`/zone2/notes/...`) 요청: 판정기 `zone_access_denied` / 서버 함수 `HTTP 403 Forbidden`.
  - 일반 학생의 강사 공지 구역 수정/삭제(`PUT`/`DELETE`): `zone_access_denied` / `HTTP 403 Forbidden`.
  - 임의 기능 키워드 경로(`/api/notes/export`, `admin` 등): `unknown_route`.
- **실행 및 상태**:
  - 실행 명령: `npm run test:package` 및 `npm run decider:test`
  - 상태: **로컬 검증 완료**.

#### [9단계] 도플갱어 다량 조회 탐지 검증
- **정상 요청 (관찰 유지)**: 10분 구간 내 120건 이하의 조회
  - 판정 결과: `{ action: 'observe' }`.
- **금지/탐지 요청 (회수 제안)**: 10분 구간 내 120건 초과(121건 이상) 폭주 조회
  - 판정 결과: `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: '...' }`.
- **실행 및 상태**:
  - 실행 명령: `npm run detect:test`
  - 상태: **로컬 가상 사건 탐지 시험 통과 완료** (운영 반 엔진의 실제 사건 전달 및 세션 강제 회수는 **미실행 · 운영 반 엔진 전달 연결 전**).

---

### 2. 한눈에 보는 복구 후 검증 결과표

| 단계 | 항목 | 정상 요청 (기대 동작) | 금지 요청 (차단 동작) | 로컬 시험 실행 결과 | 실제 운영 연동 상태 |
|---|---|---|---|---|---|
| **1~2단계** | 정적 가상 메모 보호 | 빌드 메타데이터 생성 | 비로그인 `/data.json` 가상 메모 노출 차단 | 통과 (`npm run test:r5`) | 배포 확인 완료 |
| **3단계** | JWT 토큰 검증 | 유효 토큰 시 메모 조회 허용 | 비로그인 시 `HTTP 401` 차단 | 통과 (서버 함수 검증) | 배포 확인 완료 |
| **4단계** | 자료 API 소유자 격리 | 시험 계정 B 본인 메모 허용 | B가 A 메모 접근 시 `HTTP 403` 차단 | 통과 (서버 함수 검증) | 배포 확인 완료 |
| **5단계** | 원본 API 직접 권한 회수 | 서버 함수 경유 요청 허용 | `originalApiUrl` 직접 요청 `401/403` 차단 | 통과 (`schema.sql` 권한 회수) | 배포 확인 완료 |
| **6단계** | 기기 등록 판정 | 등록 기기 `allow` | 미등록 기기 `deny` (`device_not_registered`) | 통과 (`npm run decider:test`) | **미실행** (심판 검증 항목) |
| **7단계** | 복합 이상 접속 재인증 | 재인증 완료 시 `allow` | 복합 이상 징후 시 `step_up` 요구 | 통과 (`npm run fixture:7`) | **미실행** (엔진 계약 준비 전) |
| **8단계** | 구역 분리 및 공지 보호 | A 메모 및 공지 읽기 허용 | 타 구역 및 공지 쓰기 `zone_access_denied` 차단 | 통과 (`npm run decider:test`) | 배포 확인 완료 |
| **9단계** | 도플갱어 폭주 조회 탐지 | 120건 이하 `observe` | 121건 이상 `propose_revocation` 제안 | 통과 (`npm run detect:test`) | **미실행** (엔진 회수 연결 전) |

---

### 3. 복구 후 로컬 일괄 재실행 명령

```bash
npm run test:package; npm run decider:test; npm run detect:test; npm run fixture:7; npm run test:r5
```
- 모든 로컬 단위 시험과 가상 판정/탐지 시험이 오류 없이 정상 통과하는지 순차적으로 검증합니다.
- *(주의: 로컬 가상 요청 시험의 성공은 실제 심판 판정이나 운영 반 엔진 통과 증거가 아니며, 미실행 항목은 실제 평가 환경에서 별도 검증됩니다.)*

