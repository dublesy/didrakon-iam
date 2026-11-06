package com.didrakon.iam.api.support

import org.springframework.http.HttpStatus

/** 모든 /api 응답의 공통 형식. 성공이면 data, 실패면 error 가 채워진다 */
data class ApiResponse<T>(
    val success: Boolean,
    val data: T?,
    val error: ApiError?,
) {
    companion object {
        fun <T> ok(data: T): ApiResponse<T> = ApiResponse(true, data, null)

        fun error(code: String, message: String, fields: Map<String, String>? = null): ApiResponse<Nothing> =
            ApiResponse(false, null, ApiError(code, message, fields))
    }
}

/** 클라이언트에 보여도 되는 오류 정보만 담는다 (스택 트레이스·내부 사유 제외) */
data class ApiError(val code: String, val message: String, val fields: Map<String, String>? = null)

/** API 계층에서 바로 응답 상태를 정하는 예외 (인가 실패 등) */
class ApiException(val status: HttpStatus, val code: String, message: String) : RuntimeException(message)
