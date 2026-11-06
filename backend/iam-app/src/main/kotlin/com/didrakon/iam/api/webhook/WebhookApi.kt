package com.didrakon.iam.api.webhook

import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.webhook.DeliveryStatus
import com.didrakon.iam.webhook.WebhookDelivery
import com.didrakon.iam.webhook.WebhookService
import com.didrakon.iam.webhook.WebhookSpec
import com.didrakon.iam.webhook.WebhookSubscription
import com.didrakon.iam.webhook.WebhookWithSecret
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

/** eventTypes 는 구독할 유형 목록. ["*"] 이면 전체 */
data class WebhookRequest(
    @field:NotBlank @field:Size(max = 200) val name: String,
    @field:NotBlank @field:Size(max = 500) val url: String,
    @field:NotEmpty val eventTypes: List<String>,
) {
    fun spec() = WebhookSpec(name, url, eventTypes)
}

/** 비밀값은 담지 않는다 */
data class WebhookResponse(
    val webhookId: Long,
    val name: String,
    val url: String,
    val eventTypes: List<String>,
    val isActive: Boolean,
    val createdAt: Instant,
    val createdBy: Long?,
    /** 최근 7일 동안 만든 전달의 상태별 수 */
    val recentCounts: Map<String, Int>,
) {
    companion object {
        fun from(s: WebhookSubscription, counts: Map<String, Int> = emptyMap()) =
            WebhookResponse(s.subscriptionId, s.name, s.url, s.eventTypes, s.isActive, s.createdAt, s.createdBy, counts)
    }
}

/** 비밀값 원문. 만들 때·교체할 때만 한 번 준다 */
data class WebhookSecretResponse(val webhook: WebhookResponse, val secret: String) {
    companion object {
        fun from(r: WebhookWithSecret) = WebhookSecretResponse(WebhookResponse.from(r.subscription), r.secret)
    }
}

data class WebhookDeliveryResponse(
    val deliveryId: Long,
    val webhookId: Long,
    val eventId: String,
    val eventType: String,
    val status: DeliveryStatus,
    val attempts: Int,
    val nextAttemptAt: Instant,
    val lastStatusCode: Int?,
    val lastError: String?,
    val createdAt: Instant,
    val deliveredAt: Instant?,
) {
    companion object {
        fun from(d: WebhookDelivery) = WebhookDeliveryResponse(
            d.deliveryId, d.subscriptionId, d.eventId, d.eventType, d.status, d.attempts, d.nextAttemptAt, d.lastStatusCode, d.lastError, d.createdAt, d.deliveredAt,
        )
    }
}

/** 외부 webhook 구독·전달 기록 */
@RestController
@RequestMapping("/api/v1")
class WebhookApi(private val webhookService: WebhookService) {
    @GetMapping("/webhooks")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.READ)
    fun webhooks() = ApiResponse.ok(webhookService.subscriptions().map { WebhookResponse.from(it.subscription, it.recentCounts) })

    @PostMapping("/webhooks")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.CREATE)
    fun create(@Valid @RequestBody r: WebhookRequest) = ApiResponse.ok(WebhookSecretResponse.from(webhookService.create(r.spec())))

    @PutMapping("/webhooks/{webhookId}")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.UPDATE)
    fun update(@PathVariable webhookId: Long, @Valid @RequestBody r: WebhookRequest) =
        ApiResponse.ok(WebhookResponse.from(webhookService.update(webhookId, r.spec())))

    @PostMapping("/webhooks/{webhookId}/activate")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.UPDATE)
    fun activate(@PathVariable webhookId: Long) = ApiResponse.ok(WebhookResponse.from(webhookService.changeActive(webhookId, true)))

    @PostMapping("/webhooks/{webhookId}/deactivate")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.UPDATE)
    fun deactivate(@PathVariable webhookId: Long) = ApiResponse.ok(WebhookResponse.from(webhookService.changeActive(webhookId, false)))

    @PostMapping("/webhooks/{webhookId}/rotate-secret")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.UPDATE)
    fun rotateSecret(@PathVariable webhookId: Long) = ApiResponse.ok(WebhookSecretResponse.from(webhookService.rotateSecret(webhookId)))

    /** 최근 50건 (최신순) */
    @GetMapping("/webhooks/{webhookId}/deliveries")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.READ)
    fun deliveries(@PathVariable webhookId: Long) = ApiResponse.ok(webhookService.deliveries(webhookId).map(WebhookDeliveryResponse::from))

    @PostMapping("/webhooks/{webhookId}/test")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.UPDATE)
    fun test(@PathVariable webhookId: Long) = ApiResponse.ok(WebhookDeliveryResponse.from(webhookService.sendTest(webhookId)))

    @PostMapping("/webhook-deliveries/{deliveryId}/redeliver")
    @RequiresPermission(ApiResources.WEBHOOK, PermissionAction.UPDATE)
    fun redeliver(@PathVariable deliveryId: Long) = ApiResponse.ok(WebhookDeliveryResponse.from(webhookService.redeliver(deliveryId)))
}
