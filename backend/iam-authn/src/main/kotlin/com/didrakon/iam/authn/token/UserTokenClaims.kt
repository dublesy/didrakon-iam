package com.didrakon.iam.authn.token

/**
 * 사용자 토큰(authorization code 흐름)에 넣을 추가 claim. 사번·소속·역할처럼 authn 이 모르는 값을 실행 모듈이 채운다.
 * 값은 SAS 가 인가 기록에 직렬화하므로 String·Long·Boolean·ArrayList 만 쓴다
 */
fun interface UserTokenClaims {
    fun claimsOf(subjectId: Long): Map<String, Any>
}
