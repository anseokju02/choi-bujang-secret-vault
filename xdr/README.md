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
