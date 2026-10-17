# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 심판 격리 환경에서 지킬 것

심판은 인터넷 없이 `decide.mjs` 한 파일을 불러와 경보마다 바로 답을 받습니다. 이 파일이 돌지 못하면 건수를 셀 수 없어 `XDR_DECIDE_NOT_RUNNING` 으로 끝납니다.

- `decide.mjs` 에는 `import` 문을 두지 않습니다. 필요한 패턴은 `patterns.json` 에서 파일 맨 위 상수로 옮겨 적습니다.
- 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 그 파일 안에서 혼자 계산해 답합니다. 경보 하나에 2초 안에 답합니다.
- `confidence`(확신도)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 `decide` 가 스스로 0~1 로 매긴 값입니다.
- `xdr/alerts.log` 기록과 판정기 연결은 `respond.mjs` 같은 다른 파일에서 합니다. `decide.mjs` 는 판단 결과만 돌려줍니다.

인터넷을 끈 상태에서 `npm run xdr:run -- <moduleKey>` 를 돌려도 같은 결과가 나오면 심판에서도 같은 결과가 나옵니다.

## 무차별 로그인 실습 기록

`node xdr/brute-force/read-alerts.mjs` 는 경보 28건에서 출발지·가상 계정·규칙 수준과 비밀값을 제외한 설명 범주를 읽습니다. `xdr/brute-force/patterns.json` 에는 반복 인증 실패와 여러 계정 대상 시도의 근거, 애매한 시도, 정상 사건을 구분한 기준을 적었습니다. 격리 실행 대상 `xdr/brute-force/decide.mjs` 는 import, 네트워크, 파일 읽기 없이 판단합니다.

`npm run xdr:run -- brute-force` 는 로컬 `result.json` 에 28건의 판정을 다시 기록합니다. 수업용 경보에서 block 10건, alert 9건, record 9건을 확인했습니다. `node xdr/brute-force/respond.mjs` 는 차단 후보의 시작·만료 시각과 근거 경보 ID를 `artifacts/xdr-brute-force-deny-candidates.json` 에, block·alert 19건을 `xdr/alerts.log` 에 기록합니다. 이 출력 파일들은 Git에 올리지 않습니다.

경보에 있는 출발지 주소와 가상 계정명은 운영 엔진이 확인한 ZTNA의 `subjectId`·`deviceId` 와 연결되어 있지 않습니다. 따라서 후보는 `active: false` 이며, 실제 판정기에 거부 규칙을 넣거나 접속을 차단했다고 주장하지 않습니다. 신뢰할 수 있는 사건 상관 정보가 제공되어야만 실제 정책과 연결할 수 있습니다. 위 건수는 로컬 예시 경보의 결과이며 운영 심판 점수가 아닙니다.

## 웹 주입 실습 기록

`node xdr/web-injection/read-alerts.mjs`는 수업용 웹 경보 26건의 출발지·가상 계정·규칙 수준·설명 범주만 출력합니다. 원본 URL 쿼리와 설명 원문은 출력하지 않습니다. `xdr/web-injection/patterns.json`에는 반복 SQL 구문, 스크립트 삽입, 경로 이탈, 명령 구분자와 단발·정상 요청을 구분한 근거가 있습니다. URL의 `doc-*` 이름은 실제 공격 문자열이 아니므로 그 이름만으로 차단하지 않습니다.

`npm run xdr:run -- web-injection`은 격리 실행 가능한 `decide.mjs`로 26건을 다시 분류하고 Git에 올리지 않는 `result.json`을 만듭니다. 로컬 예시에서 block 8건, alert 9건, record 9건입니다. `node xdr/web-injection/respond.mjs`는 block·alert 17건을 `xdr/alerts.log`에 기록하며, 기존 다른 모듈의 기록은 유지합니다. 차단 경보는 출발지별로 묶어 근거 ID와 15분 만료 시각을 가진 후보를 `artifacts/xdr-web-injection-deny-candidates.json`에 기록합니다. 두 출력 경로 모두 Git에서 제외됩니다.

웹 경보의 출발지 주소와 수업용 URL만으로는 운영 엔진이 확인한 `subjectId`·`deviceId`를 알아낼 수 없습니다. 후보는 `active: false`이며 `src/decider.mjs`에 주입되지 않습니다. 따라서 로컬 차단 판정 8건은 실제 접속 거부 8건을 뜻하지 않습니다. 신뢰할 수 있는 사건과 요청의 상관 계약이 제공되어야 실제 정책으로 연결할 수 있습니다.

## 알려진 취약점 악용 실습 기록

`node xdr/known-cve/read-alerts.mjs`는 수업용 경보 24건의 출발지·가상 계정·규칙 수준·설명 범주만 출력합니다. 요청 머리글·URL·설명 원문은 출력하지 않습니다. `xdr/known-cve/patterns.json`은 CVE-2021-44228 수업용 경보에서 요청 자체의 완전한 원격 조회 형태를 이름 검색·부분 표기와 구분하는 근거를 담습니다. 구문을 실행·변형하지 않으며, 이름이나 T1190 태그만으로 차단하지 않습니다.

`npm run xdr:run -- known-cve`는 import나 파일 읽기가 없는 `decide.mjs`로 경보를 재분류해 Git에서 제외된 `result.json`에 씁니다. 로컬 예시 결과는 block 8건, alert 8건, record 8건입니다. `node xdr/known-cve/respond.mjs`는 block·alert 16건을 원문 없이 `xdr/alerts.log`에 기록하고 기존 두 XDR의 로그를 보존합니다. 차단 경보는 출발지별로 묶어 근거 ID와 15분 만료 시각이 있는 후보를 `artifacts/xdr-known-cve-deny-candidates.json`에 기록합니다. 로그·후보 파일 모두 Git에서 제외됩니다.

경보 출발지와 엔진이 확인한 `subjectId`·`deviceId`를 연결하는 계약이 없어 후보는 `active: false`입니다. `src/decider.mjs`에 거부 규칙을 추가하거나 실제 접속을 차단하지 않았습니다. 로컬 건수는 운영 심판 점수가 아닙니다.

## 몰래 심어진 프로그램 실습 기록

`node xdr/persistence/read-alerts.mjs`는 수업용 지속성 경보 24건에서 출발지·가상 계정·규칙 수준·설명 범주를 읽습니다. 실행 파일의 경로와 설명 원문은 출력하지 않습니다. `xdr/persistence/patterns.json`에는 서명 없는 서비스 등록·낯선 예약 작업·기존 목록 밖 시작 항목·재부팅 뒤 남는 서비스와 정상 수업 도구를 구분하는 근거를 적었습니다. T1543/T1053 태그나 임시 파일 하나만으로 차단하지 않습니다.

`npm run xdr:run -- persistence`는 import나 파일 입출력이 없는 `decide.mjs`를 사용하여 경보를 다시 분류하고 Git에서 제외된 `result.json`을 만듭니다. 로컬 예시 결과는 block 8건, alert 8건, record 8건입니다. `node xdr/persistence/respond.mjs`는 block·alert 16건을 실행 파일 경로 없이 `xdr/alerts.log`에 기록하고 기존 XDR 로그를 보존합니다. 차단 경보는 경보의 PC 이름별로 묶어 근거 ID와 15분 만료 시각을 가진 후보를 `artifacts/xdr-persistence-quarantine-candidates.json`에 기록합니다. 두 출력 경로는 Git에서 제외됩니다.

수업용 경보의 `agent.name`은 운영 엔진이 검증한 `deviceId`가 아닙니다. 따라서 격리 후보는 `active: false`이며 `src/decider.mjs`에 추가하거나 실제 PC 접속을 막지 않았습니다. 검증된 기기 식별과 사건 연계 계약이 제공돼야 정책에 연결할 수 있습니다. 로컬 건수는 심판 점수가 아닙니다.

## 권한 가로채기 실습 기록

`node xdr/privilege/read-alerts.mjs`는 수업용 경보 26건의 출발지·가상 계정·규칙 수준·설명 범주를 출력합니다. 명령 내용이나 설명 원문은 출력하지 않습니다. `xdr/privilege/patterns.json`에는 관리자 그룹 편입과 명령 실행, 낯선 주소·시각, 여러 계정의 편입과 빠른 재가입 등 복합 근거가 있습니다. T1068/T1078 태그나 관리자라는 단어만으로 차단하지 않습니다.

`npm run xdr:run -- privilege`는 파일 입출력이나 import가 없는 `decide.mjs`로 경보를 분류합니다. 로컬 가상 경보 결과는 block 9건, alert 8건, record 9건입니다. `node xdr/privilege/respond.mjs`는 block·alert 17건을 `xdr/alerts.log`에 설명 원문 없이 기록하며 다른 모듈 로그를 보존합니다. 차단 경보는 가상 계정·출발지별로 묶어 근거 ID와 15분 만료 시각이 있는 후보를 `artifacts/xdr-privilege-deny-candidates.json`에 기록합니다. 결과·로그·후보 파일은 Git에서 제외됩니다.

가상 경보의 계정·IP는 운영 엔진이 확인한 `subjectId`·`deviceId`와 연결되지 않습니다. 후보는 `active: false`이고 실제 `src/decider.mjs`에 등록되지 않았으므로 차단 판정 9건이 실제 접속 거부를 뜻하지 않습니다. 검증된 사건 상관 계약이 제공돼야 실제 정책에 연결할 수 있습니다. 운영 심판의 결과는 포털 제출 후에만 알 수 있습니다.

## 자료 빼돌리기 실습 기록

`node xdr/exfiltration/read-alerts.mjs`는 수업용 전송 경보 30건에서 시각·출발지·가상 계정·규칙 수준·설명 범주만 출력합니다. 설명 원문과 목적지·파일 이름·전송 내용은 출력하지 않습니다. `xdr/exfiltration/patterns.json`에는 처음 보는 목적지로 짧은 시간에 많은 자료가 나간 정황, 업무 시간 밖 압축 파일 전송, 반복 대용량 전송, 평소 쓰지 않던 포트 사용과 자료실 전체 복사를 구분한 근거를 적었습니다. T1041/T1048 태그나 전송량 하나만으로 차단하지 않습니다.

`npm run xdr:run -- exfiltration`은 독립 실행되는 `decide.mjs`로 가상 경보를 다시 분류하고 Git에서 제외된 `result.json`을 생성합니다. 로컬 결과는 block 10건, alert 10건, record 10건입니다. `node xdr/exfiltration/respond.mjs`는 block·alert 20건을 설명 원문 없이 `xdr/alerts.log`에 기록하고 앞선 다섯 모듈 로그를 보존합니다. 차단 경보의 문서용 목적지 주소 8개에는 근거 ID와 15분 만료 시각이 있는 **비활성 후보**를 `artifacts/xdr-exfiltration-deny-candidates.json`에 기록합니다. 로그와 후보, 결과 파일은 Git에서 제외됩니다.

운영 판정 요청 계약에는 경보의 `dstip`과 연결되는 검증된 목적지 항목이 없습니다. 그래서 후보는 `active: false`이며 `src/decider.mjs`를 고치거나 실제 접속·목적지를 차단하지 않았습니다. 실제 정책 연결에는 신뢰할 수 있는 경보·요청 상관 정보와 목적지 정책 계약이 필요합니다. 위 건수는 로컬 가상 경보 결과이며 심판 점수는 포털 제출 후에만 확인할 수 있습니다.
