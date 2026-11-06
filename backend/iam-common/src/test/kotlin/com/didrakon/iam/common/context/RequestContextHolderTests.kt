package com.didrakon.iam.common.context

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNull

class RequestContextHolderTests {
    @Test
    fun `runWith 안에서만 컨텍스트가 보이고 끝나면 이전 값으로 돌아간다`() {
        val outer = RequestContext(actorSubjectId = 1)
        val inner = RequestContext(actorSubjectId = 2)

        RequestContextHolder.runWith(outer) {
            RequestContextHolder.runWith(inner) { assertEquals(inner, RequestContextHolder.current()) }
            assertEquals(outer, RequestContextHolder.current())
        }

        assertNull(RequestContextHolder.current())
    }

    @Test
    fun `예외가 나도 컨텍스트를 정리한다`() {
        assertThrows<IllegalStateException> {
            RequestContextHolder.runWith(RequestContext(actorSubjectId = 1)) { throw IllegalStateException() }
        }

        assertNull(RequestContextHolder.current())
    }
}
