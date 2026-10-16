// patterns.json의 조회 구문·부분 단서·정상 요청 기준을 이 파일에 옮겼다.
// 요청 문자열을 실행·변형·출력하지 않는다. CVE 번호나 T1190 태그만으로 차단하지 않는다.
const PATTERNS = Object.freeze({
  completeLookup: /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\s*:\s*\/\/[^}\s]{1,2048}\}/iu,
  partialLookup: /\$\{\s*jndi\s*:/iu,
  ambiguousDescription: /CVE-\d{4}-\d+|\bjndi\b|취약점|중괄호|점검\s*도구|라이브러리|조회\s*형태|원격\s*조회|악용\s*구문/iu,
  ambiguousUrl: /CVE-\d{4}-\d+|\bjndi\b|lookup-fragment/iu,
});

function countOf(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,6}$/u.test(value)) return Number(value);
  return null;
}

export function decide(alert) {
  const data = alert?.data;
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description : '';
  const url = typeof data?.url === 'string' && data.url.length <= 8192 ? data.url : '';
  const useragent = typeof data?.useragent === 'string' && data.useragent.length <= 8192
    ? data.useragent : '';
  const hasSource = typeof data?.srcip === 'string' && data.srcip.trim() !== '';
  const inUrl = PATTERNS.completeLookup.test(url);
  const inHeader = PATTERNS.completeLookup.test(useragent);
  const count = countOf(data?.count);

  if (hasSource && (inUrl || inHeader)) {
    return {
      action: 'block',
      confidence: inUrl && inHeader ? 0.98 : count !== null && count >= 4 ? 0.95 : 0.91,
      reason: inUrl && inHeader
        ? '요청 주소와 머리글 양쪽에서 완전한 원격 조회 구문 확인'
        : inUrl ? '요청 주소에서 완전한 원격 조회 구문 확인'
          : '요청 머리글에서 완전한 원격 조회 구문 확인',
    };
  }

  if (inUrl || inHeader || PATTERNS.partialLookup.test(url)
      || PATTERNS.partialLookup.test(useragent)
      || PATTERNS.ambiguousDescription.test(description)
      || PATTERNS.ambiguousUrl.test(url)) {
    return {
      action: 'alert', confidence: inUrl || inHeader ? 0.68 : 0.55,
      reason: '공개 취약점 관련 단서는 있지만 출발지와 완전한 요청 구문을 함께 확인하지 못함',
    };
  }

  return {
    action: 'record', confidence: 0.2,
    reason: '원격 조회 구문이나 취약점 악용 단서가 확인되지 않음',
  };
}
