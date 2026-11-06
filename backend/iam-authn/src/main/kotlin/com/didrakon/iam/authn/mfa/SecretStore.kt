package com.didrakon.iam.authn.mfa

import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.common.crypto.randomBytes
import com.didrakon.iam.common.crypto.randomUrlSafe
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.sql.Timestamp
import java.time.Clock
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 비밀값 보관소. 업무 테이블에는 비밀값 대신 [store] 가 돌려준 참조 키만 둔다 (ERD: secret_reference).
 * 지금은 DB 암호화 구현([EncryptedJdbcSecretStore])만 있고, Vault 등으로 바꿀 때 이 인터페이스를 구현한다.
 */
interface SecretStore {
    fun store(secret: ByteArray): String

    fun load(reference: String): ByteArray

    fun delete(reference: String)
}

/** 앱 키(iam.authn.secret-key, AES-256)로 AES-GCM 암호화해 secret_value 테이블에 둔다. 키가 없거나 길이가 틀리면 기동하지 않는다 */
@Component
class EncryptedJdbcSecretStore(
    private val jdbcTemplate: JdbcTemplate,
    properties: AuthnProperties,
    private val clock: Clock,
) : SecretStore {
    private val key = SecretKeySpec(decodeKey(properties.secretKey), "AES")

    override fun store(secret: ByteArray): String {
        val reference = randomUrlSafe(32)
        val iv = randomBytes(IV_LENGTH)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv)) }
        jdbcTemplate.update(
            "INSERT INTO secret_value (secret_ref, ciphertext, created_at) VALUES (?, ?, ?)",
            reference, iv + cipher.doFinal(secret), Timestamp.from(clock.instant()),
        )
        return reference
    }

    override fun load(reference: String): ByteArray {
        val stored = try {
            jdbcTemplate.queryForObject("SELECT ciphertext FROM secret_value WHERE secret_ref = ?", ByteArray::class.java, reference)
        } catch (e: EmptyResultDataAccessException) {
            null
        } ?: throw IllegalStateException("비밀값이 없습니다: $reference")
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, stored, 0, IV_LENGTH))
        }
        return cipher.doFinal(stored, IV_LENGTH, stored.size - IV_LENGTH)
    }

    override fun delete(reference: String) {
        jdbcTemplate.update("DELETE FROM secret_value WHERE secret_ref = ?", reference)
    }

    private fun decodeKey(base64: String): ByteArray {
        val bytes = runCatching { Base64.getDecoder().decode(base64) }.getOrNull()
        require(bytes != null && bytes.size == 32) {
            "iam.authn.secret-key 는 Base64 로 인코딩한 32바이트 키여야 합니다 (예: openssl rand -base64 32)"
        }
        return bytes
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val TAG_BITS = 128
    }
}
