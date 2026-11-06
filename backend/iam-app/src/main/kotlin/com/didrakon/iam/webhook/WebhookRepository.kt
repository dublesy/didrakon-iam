package com.didrakon.iam.webhook

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.support.GeneratedKeyHolder
import org.springframework.stereotype.Repository
import tools.jackson.databind.json.JsonMapper
import java.sql.ResultSet
import java.sql.Statement
import java.sql.Timestamp
import java.time.Instant

enum class DeliveryStatus { PENDING, SUCCEEDED, FAILED, DEAD }

/** 구독. [secretReference] 는 SecretStore 참조라 API 로 내보내지 않는다 */
class WebhookSubscription(
    val subscriptionId: Long,
    val name: String,
    val url: String,
    val secretReference: String,
    val eventTypes: List<String>,
    val isActive: Boolean,
    val createdAt: Instant,
    val createdBy: Long?,
) {
    fun accepts(eventType: String) = WebhookEventTypes.ALL in eventTypes || eventType in eventTypes

    /** 감사 기록용. 비밀값 참조는 넣지 않는다 */
    fun snapshot(): Map<String, Any?> = mapOf("name" to name, "url" to url, "eventTypes" to eventTypes, "isActive" to isActive)
}

class WebhookDelivery(
    val deliveryId: Long,
    val subscriptionId: Long,
    val eventId: String,
    val eventType: String,
    val status: DeliveryStatus,
    val attempts: Int,
    val nextAttemptAt: Instant,
    val lastStatusCode: Int?,
    val lastError: String?,
    val createdAt: Instant,
    val deliveredAt: Instant?,
)

/** 보낼 차례가 된 전달 한 건과 받는 곳 */
class DueDelivery(
    val deliveryId: Long,
    val eventType: String,
    val payload: String,
    val attempts: Int,
    val url: String,
    val secretReference: String,
)

/** webhook_subscription·webhook_delivery (V15) JDBC 접근. 트랜잭션은 부르는 쪽을 따른다 */
@Repository
class WebhookRepository(private val jdbc: JdbcTemplate, private val jsonMapper: JsonMapper) {
    private val subscriptionMapper = RowMapper { rs, _ ->
        WebhookSubscription(
            subscriptionId = rs.getLong("subscription_id"),
            name = rs.getString("name"),
            url = rs.getString("url"),
            secretReference = rs.getString("secret_reference"),
            eventTypes = jsonMapper.readTree(rs.getString("event_types")).toList().map { it.asString() },
            isActive = rs.getBoolean("is_active"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            createdBy = rs.getLong("created_by").takeUnless { rs.wasNull() },
        )
    }

    private val deliveryMapper = RowMapper { rs, _ ->
        WebhookDelivery(
            deliveryId = rs.getLong("delivery_id"),
            subscriptionId = rs.getLong("subscription_id"),
            eventId = rs.getString("event_id"),
            eventType = rs.getString("event_type"),
            status = DeliveryStatus.valueOf(rs.getString("status")),
            attempts = rs.getInt("attempts"),
            nextAttemptAt = rs.getTimestamp("next_attempt_at").toInstant(),
            lastStatusCode = rs.getInt("last_status_code").takeUnless { rs.wasNull() },
            lastError = rs.getString("last_error"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            deliveredAt = rs.instantOrNull("delivered_at"),
        )
    }

    fun subscriptions(): List<WebhookSubscription> =
        jdbc.query("SELECT * FROM webhook_subscription ORDER BY subscription_id", subscriptionMapper)

    fun activeSubscriptions(): List<WebhookSubscription> =
        jdbc.query("SELECT * FROM webhook_subscription WHERE is_active = TRUE", subscriptionMapper)

    fun findSubscription(subscriptionId: Long): WebhookSubscription? =
        jdbc.query("SELECT * FROM webhook_subscription WHERE subscription_id = ?", subscriptionMapper, subscriptionId).firstOrNull()

    fun insertSubscription(name: String, url: String, secretReference: String, eventTypes: List<String>, createdAt: Instant, createdBy: Long?): Long {
        val keys = GeneratedKeyHolder()
        jdbc.update({ connection ->
            connection.prepareStatement(
                """
                INSERT INTO webhook_subscription (name, url, secret_reference, event_types, is_active, created_at, created_by)
                VALUES (?, ?, ?, ?, TRUE, ?, ?)
                """,
                Statement.RETURN_GENERATED_KEYS,
            ).apply {
                setString(1, name)
                setString(2, url)
                setString(3, secretReference)
                setString(4, jsonMapper.writeValueAsString(eventTypes))
                setTimestamp(5, Timestamp.from(createdAt))
                setObject(6, createdBy)
            }
        }, keys)
        return keys.key?.toLong() ?: throw IllegalStateException("webhook_subscription 키를 받지 못했습니다")
    }

    fun updateSubscription(subscriptionId: Long, name: String, url: String, eventTypes: List<String>) {
        jdbc.update(
            "UPDATE webhook_subscription SET name = ?, url = ?, event_types = ? WHERE subscription_id = ?",
            name, url, jsonMapper.writeValueAsString(eventTypes), subscriptionId,
        )
    }

    fun updateActive(subscriptionId: Long, active: Boolean) {
        jdbc.update("UPDATE webhook_subscription SET is_active = ? WHERE subscription_id = ?", active, subscriptionId)
    }

    fun updateSecretReference(subscriptionId: Long, secretReference: String) {
        jdbc.update("UPDATE webhook_subscription SET secret_reference = ? WHERE subscription_id = ?", secretReference, subscriptionId)
    }

    fun insertDelivery(subscriptionId: Long, eventId: String, eventType: String, payload: String, now: Instant): Long {
        val keys = GeneratedKeyHolder()
        jdbc.update({ connection ->
            connection.prepareStatement(
                """
                INSERT INTO webhook_delivery (subscription_id, event_id, event_type, payload, status, attempts, next_attempt_at, created_at)
                VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)
                """,
                Statement.RETURN_GENERATED_KEYS,
            ).apply {
                setLong(1, subscriptionId)
                setString(2, eventId)
                setString(3, eventType)
                setString(4, payload)
                setTimestamp(5, Timestamp.from(now))
                setTimestamp(6, Timestamp.from(now))
            }
        }, keys)
        return keys.key?.toLong() ?: throw IllegalStateException("webhook_delivery 키를 받지 못했습니다")
    }

    fun deliveries(subscriptionId: Long, limit: Int): List<WebhookDelivery> = jdbc.query(
        "SELECT * FROM webhook_delivery WHERE subscription_id = ? ORDER BY delivery_id DESC LIMIT ?",
        deliveryMapper, subscriptionId, limit,
    )

    fun findDelivery(deliveryId: Long): WebhookDelivery? =
        jdbc.query("SELECT * FROM webhook_delivery WHERE delivery_id = ?", deliveryMapper, deliveryId).firstOrNull()

    /** 구독별·상태별 전달 수 ([since] 이후 만든 것) */
    fun statusCounts(since: Instant): Map<Long, Map<String, Int>> {
        val rows = jdbc.query(
            "SELECT subscription_id, status, COUNT(*) AS cnt FROM webhook_delivery WHERE created_at >= ? GROUP BY subscription_id, status",
            { rs, _ -> Triple(rs.getLong("subscription_id"), rs.getString("status"), rs.getInt("cnt")) },
            Timestamp.from(since),
        )
        return rows.groupBy({ it.first }, { it.second to it.third }).mapValues { (_, pairs) -> pairs.toMap() }
    }

    /** 보낼 차례가 된 전달. 구독마다 끝나지 않은 가장 앞 전달만 고른다 (순서 보장). 꺼진 구독의 전달은 다시 켤 때까지 그대로 둔다 */
    fun due(now: Instant, limit: Int): List<DueDelivery> = jdbc.query(
        """
        SELECT d.delivery_id, d.event_type, d.payload, d.attempts, s.url, s.secret_reference
        FROM webhook_delivery d JOIN webhook_subscription s ON s.subscription_id = d.subscription_id
        WHERE d.status IN ('PENDING', 'FAILED') AND d.next_attempt_at <= ? AND s.is_active = TRUE
          AND NOT EXISTS (
            SELECT 1 FROM webhook_delivery p
            WHERE p.subscription_id = d.subscription_id AND p.status IN ('PENDING', 'FAILED') AND p.delivery_id < d.delivery_id
          )
        ORDER BY d.next_attempt_at, d.delivery_id
        LIMIT ?
        """,
        { rs, _ ->
            DueDelivery(
                rs.getLong("delivery_id"), rs.getString("event_type"), rs.getString("payload"),
                rs.getInt("attempts"), rs.getString("url"), rs.getString("secret_reference"),
            )
        },
        Timestamp.from(now), limit,
    )

    fun markSucceeded(deliveryId: Long, attempts: Int, statusCode: Int, now: Instant) {
        jdbc.update(
            """
            UPDATE webhook_delivery SET status = 'SUCCEEDED', attempts = ?, last_status_code = ?, last_error = NULL, delivered_at = ?
            WHERE delivery_id = ?
            """,
            attempts, statusCode, Timestamp.from(now), deliveryId,
        )
    }

    fun markFailed(deliveryId: Long, status: DeliveryStatus, attempts: Int, nextAttemptAt: Instant, statusCode: Int?, error: String) {
        jdbc.update(
            "UPDATE webhook_delivery SET status = ?, attempts = ?, next_attempt_at = ?, last_status_code = ?, last_error = ? WHERE delivery_id = ?",
            status.name, attempts, Timestamp.from(nextAttemptAt), statusCode, error.take(200), deliveryId,
        )
    }

    /** 다시 보내기: 재시도 횟수를 처음부터 센다 */
    /** 끝난(성공·포기) 전달 중 [before] 이전에 만든 것을 지운다. 지운 수 */
    fun purgeFinished(before: Instant): Int = jdbc.update(
        "DELETE FROM webhook_delivery WHERE status IN ('SUCCEEDED', 'DEAD') AND created_at < ?",
        java.sql.Timestamp.from(before),
    )

    fun resetForRedelivery(deliveryId: Long, now: Instant) {
        jdbc.update(
            "UPDATE webhook_delivery SET status = 'PENDING', attempts = 0, next_attempt_at = ?, last_error = NULL WHERE delivery_id = ?",
            Timestamp.from(now), deliveryId,
        )
    }

    private fun ResultSet.instantOrNull(column: String): Instant? = getTimestamp(column)?.toInstant()
}
