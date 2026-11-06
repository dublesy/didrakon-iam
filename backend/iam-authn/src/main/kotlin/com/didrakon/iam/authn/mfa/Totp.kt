package com.didrakon.iam.authn.mfa

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 6238 TOTP (HMAC-SHA1, 30초, 6자리). 인증 앱(Google Authenticator 등) 기본값과 같다 */
object Totp {
    private const val PERIOD_SECONDS = 30L
    private const val DIGITS = 6

    fun code(secret: ByteArray, at: Instant, digits: Int = DIGITS): String = codeForCounter(secret, at.epochSecond / PERIOD_SECONDS, digits)

    fun verify(secret: ByteArray, code: String, at: Instant, window: Int = 1): Boolean = matchingStep(secret, code, at, window) != null

    /**
     * 코드가 맞은 시간 구간(30초 단위 카운터). 맞지 않으면 null.
     * 시계 오차를 감안해 앞뒤 [window] 구간까지 허용하고, 비교는 상수 시간으로 한다.
     * 재사용 방지는 호출 측이 이 값을 마지막 사용 구간과 비교해 한다.
     */
    fun matchingStep(secret: ByteArray, code: String, at: Instant, window: Int = 1): Long? {
        if (code.length != DIGITS || !code.all(Char::isDigit)) return null
        val counter = at.epochSecond / PERIOD_SECONDS
        return (-window..window).map { counter + it }.firstOrNull { step ->
            MessageDigest.isEqual(codeForCounter(secret, step, DIGITS).toByteArray(), code.toByteArray())
        }
    }

    private fun codeForCounter(secret: ByteArray, counter: Long, digits: Int): String {
        val hash = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(secret, "HmacSHA1")) }
            .doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        val offset = hash.last().toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)
        var modulus = 1
        repeat(digits) { modulus *= 10 }
        return (binary % modulus).toString().padStart(digits, '0')
    }
}

/** RFC 4648 Base32 (패딩 없음). 인증 앱에 등록하는 비밀값 표기 */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(bytes: ByteArray): String {
        val result = StringBuilder()
        var buffer = 0
        var bits = 0
        bytes.forEach { byte ->
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                result.append(ALPHABET[(buffer shr (bits - 5)) and 0x1f])
                bits -= 5
            }
        }
        if (bits > 0) result.append(ALPHABET[(buffer shl (5 - bits)) and 0x1f])
        return result.toString()
    }
}
