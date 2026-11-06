package com.didrakon.iam.common.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** 토큰·세션 키·API 키처럼 원문을 저장하지 않는 값의 저장용 hash (SHA-256 소문자 hex, 64자) */
fun sha256Hex(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }

private val secureRandom = SecureRandom()

/** URL 에 그대로 쓸 수 있는 무작위 문자열 */
fun randomUrlSafe(byteLength: Int = 32): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(byteLength).also(secureRandom::nextBytes))

fun randomBytes(byteLength: Int): ByteArray = ByteArray(byteLength).also(secureRandom::nextBytes)
