// patterns.json의 기준을 심판의 단일 파일 격리 실행에 맞게 옮겼다.
// 수업용 doc-* 주소는 공격 원문이 아니므로 그 이름만으로 차단하지 않는다.
const PATTERNS = Object.freeze({
  repeatedCount: 5,
  sql: /SQL\s*(?:구문(?:\s*표기)?|표식)|데이터베이스\s*조회를?\s*이어\s*붙/u,
  script: /스크립트\s*(?:삽입\s*표기|표식)/u,
  traversal: /경로(?:를\s*여러\s*단계\s*거슬러\s*올라가는|\s*이탈\s*표기)/u,
  command: /명령\s*구분자\s*표기/u,
  repeated: /반복됐|반복되었|번\s*반복|연속\s*요청|(?:같은|한)\s*주소에서|번\s*(?:들어왔|나왔)/u,
  notRepeated: /반복은\s*없|반복되지\s*않/u,
  ambiguous: /따옴표|\bselect\b|스크립트|경로에\s*up\b|주소가\s*평소보다\s*깁|SQL|이상한\s*검색|주입처럼|구분\s*문자/iu,
});

function countOf(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,6}$/u.test(value)) return Number(value);
  return null;
}

function literalPayloadKind(url) {
  if (typeof url !== 'string' || url.length > 8192) return null;
  // 실제 URL에 구문이 담긴 경우만 보조 근거로 삼는다. 문자열을 실행하거나 출력하지 않는다.
  let candidate = url;
  for (let i = 0; i < 2; i += 1) {
    try { candidate = decodeURIComponent(candidate); } catch { break; }
  }
  if (/(?:\bunion\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+(?:1\s*=\s*1|['"]?\w+['"]?\s*=\s*['"]?\w+)|;\s*(?:drop|delete|update|insert)\b)/iu.test(candidate)) return 'SQL 주입';
  if (/<\s*script\b|\bon(?:error|load)\s*=|javascript\s*:/iu.test(candidate)) return '스크립트 삽입';
  if (/(?:^|[/?])(?:\.\.\/){2,}/u.test(candidate)) return '경로 이탈';
  if (/[;&|]\s*(?:cat|curl|wget|whoami|bash|sh)\b/iu.test(candidate)) return '명령 삽입';
  return null;
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description : '';
  const count = countOf(alert?.data?.count);
  const sourcePresent = typeof alert?.data?.srcip === 'string'
    && alert.data.srcip.trim() !== '';
  const urlPresent = typeof alert?.data?.url === 'string'
    && alert.data.url.trim() !== '';
  const literalKind = literalPayloadKind(alert?.data?.url);
  const describedKind = PATTERNS.sql.test(description) ? 'SQL 주입'
    : PATTERNS.script.test(description) ? '스크립트 삽입'
      : PATTERNS.traversal.test(description) ? '경로 이탈'
        : PATTERNS.command.test(description) ? '명령 삽입' : null;
  const kind = describedKind ?? literalKind;
  const repeated = PATTERNS.repeated.test(description)
    && !PATTERNS.notRepeated.test(description);

  if (sourcePresent && urlPresent && kind && repeated
      && count !== null && count >= PATTERNS.repeatedCount) {
    return {
      action: 'block', confidence: count >= 10 ? 0.94 : 0.88,
      reason: `${kind} 징후가 한 출발지에서 ${count}건 반복됨`,
    };
  }
  // 출발지나 URL이 빠져도 의심 신호 자체는 조사 대상으로 남긴다.
  if (kind || PATTERNS.ambiguous.test(description)) {
    return {
      action: 'alert', confidence: kind ? 0.66 : 0.53,
      reason: '웹 요청에 추가 확인할 단서가 있으나 반복 주입 근거는 부족함',
    };
  }
  return {
    action: 'record', confidence: 0.2,
    reason: '주입 또는 경로 이탈을 의심할 근거가 확인되지 않음',
  };
}
