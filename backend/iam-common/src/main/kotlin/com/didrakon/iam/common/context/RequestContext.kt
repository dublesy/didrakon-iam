package com.didrakon.iam.common.context

/** 지금 처리 중인 요청의 행위자와 출처. 감사 기록이 읽는다 */
data class RequestContext(
    /** 요청한 subject. 배치·시스템 작업은 null */
    val actorSubjectId: Long? = null,
    val traceId: String? = null,
    val ipAddress: String? = null,
    val userAgent: String? = null,
    val deviceId: String? = null,
)

/**
 * 스레드 단위 [RequestContext] 보관소. 웹 요청은 필터가, 배치는 작업 시작 시 [runWith] 로 채운다.
 * 비어 있으면 시스템 작업으로 본다.
 */
object RequestContextHolder {
    private val holder = ThreadLocal<RequestContext>()

    fun current(): RequestContext? = holder.get()

    /** [context] 를 설정한 채 [block] 을 실행하고, 끝나면 이전 값으로 되돌린다 */
    fun <T> runWith(context: RequestContext, block: () -> T): T {
        val previous = holder.get()
        holder.set(context)
        try {
            return block()
        } finally {
            if (previous == null) holder.remove() else holder.set(previous)
        }
    }
}
