package com.didrakon.iam.authn.mfa

import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TotpTests {
    /** RFC 6238 부록 B 의 SHA1 시험 벡터 */
    private val rfcSecret = "12345678901234567890".toByteArray()

    @Test
    fun `RFC 6238 시험 벡터와 같은 코드를 만든다`() {
        assertEquals("94287082", Totp.code(rfcSecret, Instant.ofEpochSecond(59), digits = 8))
        assertEquals("07081804", Totp.code(rfcSecret, Instant.ofEpochSecond(1111111109), digits = 8))
        assertEquals("89005924", Totp.code(rfcSecret, Instant.ofEpochSecond(1234567890), digits = 8))
    }

    @Test
    fun `앞뒤 30초 구간까지 허용하고 그 밖과 형식이 틀린 코드는 거부한다`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val previous = Totp.code(rfcSecret, now.minusSeconds(30))

        assertTrue(Totp.verify(rfcSecret, Totp.code(rfcSecret, now), now))
        assertTrue(Totp.verify(rfcSecret, previous, now))
        assertFalse(Totp.verify(rfcSecret, Totp.code(rfcSecret, now.minusSeconds(90)), now))
        assertFalse(Totp.verify(rfcSecret, "12a456", now))
    }

    @Test
    fun `맞은 코드의 시간 구간을 돌려줘 재사용 여부를 판단할 수 있게 한다`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val current = now.epochSecond / 30

        assertEquals(current, Totp.matchingStep(rfcSecret, Totp.code(rfcSecret, now), now))
        assertEquals(current - 1, Totp.matchingStep(rfcSecret, Totp.code(rfcSecret, now.minusSeconds(30)), now))
        assertEquals(null, Totp.matchingStep(rfcSecret, "000000".takeIf { it != Totp.code(rfcSecret, now) } ?: "111111", now))
    }

    @Test
    fun `Base32 는 RFC 4648 시험 벡터와 같다`() {
        assertEquals("MZXW6YTBOI", Base32.encode("foobar".toByteArray()))
        assertEquals("MY", Base32.encode("f".toByteArray()))
    }
}
