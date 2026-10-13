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
