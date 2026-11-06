package com.didrakon.iam.webhook

import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.common.context.RequestContextHolder
import com.didrakon.iam.common.crypto.randomUrlSafe
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.event.AdminChangeEvent
import org.springframework.context.ApplicationEventPublisher
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URI
import java.time.Clock
import java.time.Duration

data class WebhookSpec(val name: String, val url: String, val eventTypes: List<String>)

/** 구독과 최근 [WebhookService.COUNT_WINDOW] 동안 만든 전달의 상태별 수 */
class WebhookSubscriptionView(val subscription: WebhookSubscription, val recentCounts: Map<String, Int>)

/** 비밀값 원문은 만들 때·교체할 때 이 결과로 한 번만 돌려준다 */
class WebhookWithSecret(val subscription: WebhookSubscription, val secret: String)

/**
 * webhook 구독 관리. 구독 변경은 [AdminChangeEvent]("WEBHOOK") 로 감사에 남기며, 비밀값은 넣지 않는다.
 * 비밀값은 [SecretStore] 에 암호화해 두고 구독에는 참조만 둔다.
 */
@Service
@Transactional
class WebhookService(
    private val repository: WebhookRepository,
    private val outbox: WebhookOutbox,
    private val secretStore: SecretStore,
    private val addressGuard: WebhookAddressGuard,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    @Transactional(readOnly = true)
    fun subscriptions(): List<WebhookSubscriptionView> {
        val counts = repository.statusCounts(clock.instant().minus(COUNT_WINDOW))
        return repository.subscriptions().map { WebhookSubscriptionView(it, counts[it.subscriptionId].orEmpty()) }
    }

    fun create(spec: WebhookSpec): WebhookWithSecret {
        val valid = validate(spec)
        val secret = newSecret()
        val id = repository.insertSubscription(
            valid.name, valid.url, secretStore.store(secret.toByteArray()), valid.eventTypes, clock.instant(), RequestContextHolder.current()?.actorSubjectId,
        )
        val created = find(id)
        eventPublisher.publishEvent(AdminChangeEvent(TARGET, id, "CREATE", null, created.snapshot()))
        return WebhookWithSecret(created, secret)
    }

    fun update(subscriptionId: Long, spec: WebhookSpec): WebhookSubscription {
        val before = find(subscriptionId)
        val valid = validate(spec)
        repository.updateSubscription(subscriptionId, valid.name, valid.url, valid.eventTypes)
        val after = find(subscriptionId)
        eventPublisher.publishEvent(AdminChangeEvent(TARGET, subscriptionId, "UPDATE", before.snapshot(), after.snapshot()))
        return after
    }

    fun changeActive(subscriptionId: Long, active: Boolean): WebhookSubscription {
        val before = find(subscriptionId)
        if (before.isActive == active) return before
        repository.updateActive(subscriptionId, active)
        val after = find(subscriptionId)
        eventPublisher.publishEvent(AdminChangeEvent(TARGET, subscriptionId, if (active) "ACTIVATE" else "DEACTIVATE", before.snapshot(), after.snapshot()))
        return after
    }

    /** 새 비밀값으로 바꾸고 이전 값은 지운다. 바로 다음 전송부터 새 값으로 서명한다 */
    fun rotateSecret(subscriptionId: Long): WebhookWithSecret {
        val subscription = find(subscriptionId)
        val secret = newSecret()
        repository.updateSecretReference(subscriptionId, secretStore.store(secret.toByteArray()))
        secretStore.delete(subscription.secretReference)
        eventPublisher.publishEvent(AdminChangeEvent(TARGET, subscriptionId, "ROTATE_SECRET", null, null))
        return WebhookWithSecret(find(subscriptionId), secret)
    }

    @Transactional(readOnly = true)
    fun deliveries(subscriptionId: Long): List<WebhookDelivery> {
        find(subscriptionId)
        return repository.deliveries(subscriptionId, RECENT_DELIVERIES)
    }

    /** 상태와 관계없이 지금 다시 보내도록 되돌린다 (재시도 횟수도 처음부터) */
    fun redeliver(deliveryId: Long): WebhookDelivery {
        repository.findDelivery(deliveryId) ?: throw NotFoundException("웹훅 전달", deliveryId)
        repository.resetForRedelivery(deliveryId, clock.instant())
        return repository.findDelivery(deliveryId) ?: throw NotFoundException("웹훅 전달", deliveryId)
    }

    /** 구독 확인용 webhook.test 이벤트를 넣는다. 다음 전달 작업에서 보낸다 */
    fun sendTest(subscriptionId: Long): WebhookDelivery {
        val subscription = find(subscriptionId)
        if (!subscription.isActive) throw BusinessRuleException("꺼진 웹훅에는 보낼 수 없습니다. 먼저 켜세요")
        val deliveryId = outbox.enqueueTest(subscription)
        return repository.findDelivery(deliveryId) ?: throw NotFoundException("웹훅 전달", deliveryId)
    }

    private fun find(subscriptionId: Long): WebhookSubscription =
        repository.findSubscription(subscriptionId) ?: throw NotFoundException("웹훅", subscriptionId)

    private fun validate(spec: WebhookSpec): WebhookSpec {
        val name = spec.name.trim()
        if (name.isEmpty()) throw BusinessRuleException("이름이 필요합니다")
        val url = spec.url.trim()
        val parsed = runCatching { URI(url) }.getOrNull()
        if (parsed?.scheme !in setOf("http", "https") || parsed?.host.isNullOrBlank()) {
            throw BusinessRuleException("웹훅 주소는 http(s) 절대 주소여야 합니다")
        }
        // 내부망 주소는 등록부터 막는다. 아직 풀리지 않는 이름은 받아 두고, 보낼 때 다시 확인한다
        try {
            addressGuard.check(url)
        } catch (e: BlockedAddressException) {
            throw BusinessRuleException("내부망 주소(사설·루프백·링크 로컬 등)로는 웹훅을 보낼 수 없습니다")
        } catch (_: java.net.UnknownHostException) {
        }
        val types = spec.eventTypes.map { it.trim() }.distinct()
        if (types.isEmpty()) throw BusinessRuleException("받을 이벤트를 하나 이상 고르세요")
        val unknown = types.filter { it != WebhookEventTypes.ALL && it !in WebhookEventTypes.SUBSCRIBABLE }
        if (unknown.isNotEmpty()) throw BusinessRuleException("알 수 없는 이벤트 유형입니다: ${unknown.joinToString()}")
        return WebhookSpec(name, url, if (WebhookEventTypes.ALL in types) listOf(WebhookEventTypes.ALL) else types)
    }

    private fun newSecret() = "whsec_" + randomUrlSafe(32)

    companion object {
        const val TARGET = "WEBHOOK"
        const val RECENT_DELIVERIES = 50
        val COUNT_WINDOW: Duration = Duration.ofDays(7)
    }
}
