package com.didrakon.iam.common.error

/** 도메인 예외의 최상위. 메시지는 클라이언트에 노출해도 되는 내용만 담는다 */
abstract class IamException(message: String) : RuntimeException(message)

/** 요청한 대상이 없다 */
class NotFoundException(target: String, id: Any) : IamException("$target 을(를) 찾을 수 없습니다: $id")

/** 도메인 규칙 위반 */
class BusinessRuleException(message: String) : IamException(message)
