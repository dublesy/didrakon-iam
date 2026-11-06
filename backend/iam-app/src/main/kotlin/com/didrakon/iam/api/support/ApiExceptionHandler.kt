package com.didrakon.iam.api.support

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import org.slf4j.LoggerFactory
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingServletRequestParameterException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException
import org.springframework.web.servlet.resource.NoResourceFoundException

/** 예외를 공통 응답 형식으로 바꾼다. 예상하지 못한 예외는 내용을 숨기고 로그에만 남긴다 */
@RestControllerAdvice(basePackages = ["com.didrakon.iam.api"])
class ApiExceptionHandler {
    private val log = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(ApiException::class)
    fun api(e: ApiException) = respond(e.status, e.code, e.message.orEmpty())

    @ExceptionHandler(NotFoundException::class)
    fun notFound(e: NotFoundException) = respond(HttpStatus.NOT_FOUND, "NOT_FOUND", e.message.orEmpty())

    @ExceptionHandler(BusinessRuleException::class)
    fun businessRule(e: BusinessRuleException) = respond(HttpStatus.CONFLICT, "BUSINESS_RULE", e.message.orEmpty())

    /** 고유 키 충돌 등. DB 메시지에는 스키마 정보가 있어 그대로 내보내지 않는다 */
    @ExceptionHandler(DataIntegrityViolationException::class)
    fun integrity(e: DataIntegrityViolationException): ResponseEntity<ApiResponse<Nothing>> {
        log.info("데이터 무결성 위반: {}", e.mostSpecificCause.message)
        return respond(HttpStatus.CONFLICT, "DUPLICATE_OR_INVALID_REFERENCE", "이미 있는 값이거나 존재하지 않는 대상을 참조합니다")
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun validation(e: MethodArgumentNotValidException): ResponseEntity<ApiResponse<Nothing>> {
        val fields = e.bindingResult.fieldErrors.associate { it.field to (it.defaultMessage ?: "올바르지 않은 값") }
        return respond(HttpStatus.BAD_REQUEST, "VALIDATION", "입력값을 확인하세요", fields)
    }

    @ExceptionHandler(
        HttpMessageNotReadableException::class,
        MissingServletRequestParameterException::class,
        MethodArgumentTypeMismatchException::class,
    )
    fun badRequest(e: Exception) = respond(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "요청 형식이 올바르지 않습니다")

    @ExceptionHandler(NoResourceFoundException::class)
    fun noRoute(e: NoResourceFoundException) = respond(HttpStatus.NOT_FOUND, "NOT_FOUND", "없는 API 입니다")

    @ExceptionHandler(Exception::class)
    fun unexpected(e: Exception): ResponseEntity<ApiResponse<Nothing>> {
        log.error("처리하지 못한 예외", e)
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "요청을 처리하지 못했습니다")
    }

    private fun respond(status: HttpStatus, code: String, message: String, fields: Map<String, String>? = null) =
        ResponseEntity.status(status).body(ApiResponse.error(code, message, fields))
}
