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


## 2단계 제작 3: 공개 자료 잔존 확인

### 확인 방법
1. GitHub 최신 main 브랜치에서 기존 가상 메모 4건의 본문 문장을 검색한다.
2. Vercel의 /data.json에 접속하여 공개 여부를 확인한다.
3. /aleph.json에서 현재 단계와 배포 정보를 확인한다.
4. /api/notes가 비로그인 상태에서 접근 가능한지 확인한다.

### 직접 확인한 결과
- GitHub 최신 코드 검색에서 가상 메모 문장 4개의 결과가 0건이었다.
- /data.json은 404 NOT_FOUND를 반환했다.
- /aleph.json에서 step: 2를 확인했다.
- /api/notes는 인증 없이 가상 메모 4건을 반환했다.

### 남아 있는 한계
현재 GitHub 파일과 최신 배포에서 정적 메모 노출을 제거했다.

그러나 /api/notes는 여전히 공개 API이므로
로그인하지 않은 사용자도 가상 메모를 조회할 수 있다.

또한 과거 Git 커밋과 이전 Vercel 배포에
메모 내용이 남아 있을 수 있다.
따라서 과거 노출까지 완전히 해결했다고 주장하지 않는다.

GitHub 코드 검색에는 색인에 따른 한계가 있다.
실제 심판의 보안 판정은 별도로 확인해야 한다.


## 2단계 저장점

### 현재 작동하는 기능
- 가상 메모 4건을 Supabase DB에 저장했다.
- Vercel 서버 API를 통해 웹페이지에 메모 4건을 표시한다.
- 공개 정적 파일 /data.json은 404를 반환한다.
- /aleph.json에서 step 2를 확인했다.

### 다시 확인하는 방법
1. 배포 웹페이지에서 메모 카드 4개 확인
2. /data.json에서 404 확인
3. /api/notes에서 메모 4건 확인
4. /aleph.json에서 step 2 확인

### 제출 묶음 생성 방법
- Node.js 22 이상 필요
- 로컬에서 bundle-notes.json 작성
- npm.cmd run bundle 실행
- 생성 파일: artifacts/submission.json

### 남은 약점
/api/notes는 로그인 없이 조회할 수 있다.
과거 Git 커밋 및 배포에 남은 노출 이력도
해결된 것으로 간주하지 않는다.


## 3단계 저장점

### 현재 구현한 기능
- Supabase Auth 이메일·비밀번호 로그인 및 로그아웃
- 서버에서 JWT 로그인 토큰 검증
- 비로그인 및 잘못된 토큰 요청 401 거부
- 로그인한 사용자의 메모 목록 조회
- 가상 메모 추가·조회·수정·삭제 기능
- 기존 가상 메모 4건 보존
- aleph.config.json의 step 3 및 allowedRoutes 설정

### 직접 확인한 결과
- A 계정 로그인 및 로그아웃 성공
- 비로그인 /api/notes 요청 거부 확인
- 비로그인 /api/notes/:id 요청 거부 확인
- A 계정으로 메모 4건 조회 성공
- 테스트 메모 추가·수정·삭제 성공
- /aleph.json에서 step 3 확인

### 남아 있는 보안 약점
개별 메모 API는 로그인 토큰을 검증하지만,
조회·수정·삭제 시 owner_id를 검사하지 않는다.

따라서 로그인한 다른 사용자가 메모 UUID를 알면
해당 메모에 접근할 위험이 있다.

이 문제는 이후 단계에서 소유권 검사로 보완해야 한다.

과거 Git 커밋과 이전 배포의 공개 이력은
현재 변경만으로 제거되지 않는다.

### 다시 실행하고 확인하는 방법
1. Vercel 배포 주소에서 A 계정으로 로그인한다.
2. 기존 메모 4건이 나타나는지 확인한다.
3. 테스트 메모를 추가·수정·삭제한다.
4. 시크릿 창에서 /api/notes의 401 거부를 확인한다.
5. /aleph.json에서 step 3을 확인한다.
6. 로컬에서 npm.cmd run bundle을 실행한다.


### 3단계 제출용 공격 점검

- 정적 /data.json 메모 노출 여부 점검
- 비로그인 /api/notes 접근 차단 점검
- 잘못된 로그인 토큰 거부 여부 점검
- 비로그인 개별 메모 접근 차단 점검

공격 점검은 src/attack-check.mjs에서 실제 배포 서버로
요청을 보내고 응답 상태를 기록한다.

npm.cmd run bundle 실행 시
artifacts/submission.json에 결과가 저장된다.

bundle-notes.json과 artifacts/submission.json은
GitHub에 커밋하지 않는다.


## 4단계 저장점

### 구현한 기능
- A 소유의 기존 가상 메모 4건 보존
- B 소유의 시험용 가상 메모 1건 준비
- 서버 API GET·PUT·DELETE에 owner_id 검사 적용
- 로그인 사용자의 ID와 메모 소유자가 일치할 때만 허용
- Supabase authenticated 역할에 CRUD 권한 부여
- anon 테이블 접근 권한 차단
- SELECT·INSERT·UPDATE·DELETE RLS 소유권 정책 적용

### 직접 확인한 결과
- A 계정에서 A 메모 4건 조회 성공
- B 계정에서 B 메모 1건 조회 성공
- B가 A 메모 GET 요청 시 404 NOTE_NOT_FOUND
- B가 A 메모 PUT 요청 시 404 NOTE_NOT_FOUND
- B가 A 메모 DELETE 요청 시 404 NOTE_NOT_FOUND
- B 본인의 테스트 메모 추가·수정·삭제 성공
- SQL Editor에서 RLS 역할별 조회 모의 검사 통과

### 확인 범위와 주의 사항
A/B 교차 접근 거부는 브라우저에서 직접 확인했다.
제출용 공격 점검 스크립트는 비로그인 요청을 검사한다.

Vercel 서버는 service_role을 사용하므로
서버 API의 owner_id 조건도 반드시 유지해야 한다.

RLS는 authenticated 역할의 직접 DB 접근에 적용된다.
과거 배포의 공개 이력까지 삭제한 것은 아니다.

### 재확인 및 제출
1. A/B 계정으로 로그인하여 각자 메모 확인
2. 상대방 메모 조회·수정·삭제 차단 확인
3. 시크릿 창에서 비로그인 API 401 확인
4. /aleph.json에서 step 4 확인
5. git pull --ff-only origin main
6. npm.cmd run bundle

## 5단계 저장점

### 구현 및 확인한 기능
- 브라우저의 메모 CRUD 요청은 Vercel 서버 API를 경유한다.
- 서버에서 로그인 토큰과 메모 소유자를 검증한다.
- Supabase 메모 테이블의 PUBLIC, anon, authenticated 직접 접근 권한을 회수했다.
- Vercel 서버에서 사용하는 service_role CRUD 권한은 유지했다.
- 원본 Supabase REST API 주소를 aleph.config.json에 기록했다.

### 직접 확인한 결과
- A 계정에서 가상 메모 추가·조회·수정·삭제 성공
- A 계정의 기존 메모 4건 보존
- B 계정 로그인 및 본인 메모 1건 조회 성공
- Supabase 원본 REST API를 공개 키로 직접 조회한 결과 HTTP 401
- DB 응답 코드 42501, permission denied for table aleph_vault_notes

### 보안 구조
메모 요청은 브라우저 → Vercel 서버 API → Supabase DB 순서로 처리한다.

브라우저에서 원본 메모 테이블을 직접 호출하는 권한은 차단했다. 

### 다시 확인하는 방법
1. A/B 계정으로 로그인하여 본인 메모 조회
2. 시크릿 창에서 비로그인 /api/notes 접근 거부 확인
3. Supabase 원본 REST API의 직접 조회 거부 확인
4. /aleph.json에서 step 5 확인
5. npm.cmd run bundle 실행


### 5단계 추가 점수: 브라우저 공개 키 제거

#### 구현한 기능
- 브라우저에서 Supabase SDK 직접 연결 제거
- public/index.html에서 Supabase 공개 키 제거
- public/auth-client.js에서 /api/auth 호출
- api/auth.js에서 서버 환경변수로 Supabase Auth 처리
- HttpOnly, Secure, SameSite 쿠키로 세션 갱신 정보 관리
- 기존 메모 CRUD와 소유자 검사 유지

#### 직접 확인한 결과
- A 계정 로그인 및 기존 메모 4건 조회 성공
- A 계정 새로고침 후 로그인 유지 성공
- 로그아웃 후 로그인 화면 복귀 성공
- B 계정 로그인 및 본인 메모 1건 조회 성공
- B 계정 새로고침 후 로그인 유지 성공
- 브라우저 코드의 Supabase 공개 키 제거 확인

#### 참고 사항
현재 브라우저 코드에서 공개 키를 제거했지만,
과거 Git 커밋의 공개 이력까지 삭제한 것은 아니다.
기존 서버 전용 키는 브라우저에 노출하지 않는다.


## 6단계 저장점: 등록 기기 판정

- 판정기에 전달된 deviceRegistered가 true이면 허용하고, false이거나 없으면 device_not_registered로 거부한다.
- 확인 명령: npm.cmd run decider:test
- 로컬 가상 요청 시험에서 등록 기기의 정상 요청과 미등록 기기의 거부 요청이 모두 통과했다.
- 이 시험은 판정 함수의 로컬 연습이며, 실제 심판 판정이나 실제 기기 등록 검증 결과는 아니다.
- 이번 단계에서 별도의 접속 프로그램이나 인증서를 설치하지 않았다.

## 7단계 저장점: 평소와 다른 접속 추가 확인

### 구현한 판정
- 등록되지 않은 기기는 device_not_registered 사유로 거부한다.
- 출처가 분명한 가상 사건에서 늦은 시각, 낯선 네트워크, 최근 많은 위험 사건이 함께 나타나면 step_up_required 사유로 추가 확인을 요청한다.
- 지역 정보 하나만으로 영구 거부하지 않는다.
- 추가 확인을 마쳤고 인증 후 900초 이내인 새 요청은 허용한다.
- 신호가 없거나 출처가 불분명하면 임의의 정상 지역·시간·네트워크 값으로 채우지 않는다.

### 로컬에서 확인한 결과
- npm.cmd run fixture:7: 정상 사건 allow, 복합 이상 사건 step_up
- npm.cmd run decider:test: 정상 기기, 미등록 기기, 복합 이상 접속, 추가 확인 완료 요청의 네 가지 가상 검사 통과

### 확인 범위와 다시 실행하는 방법
- 위 결과는 가상 요청으로 판정 함수를 시험한 것이며 운영 심판 판정이나 실제 위치·재인증 확인 결과는 아니다.
- 현재 실제 요청에는 지역과 네트워크 신호가 제공되지 않으므로 가상 사건의 이상 접속 규칙이 실제 접속에서 작동했다고 주장하지 않는다.
- 다시 확인할 때는 npm.cmd run fixture:7 및 npm.cmd run decider:test를 실행한다.
