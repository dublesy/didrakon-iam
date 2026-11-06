package com.didrakon.iam.api.governance

import com.didrakon.iam.api.authz.IdResponse
import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.api.support.SelfService
import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.governance.review.AccessReviewCampaign
import com.didrakon.iam.governance.review.AccessReviewDecision
import com.didrakon.iam.governance.review.AccessReviewItem
import com.didrakon.iam.governance.review.AccessReviewProgress
import com.didrakon.iam.governance.review.AccessReviewService
import com.didrakon.iam.governance.review.AccessReviewSpec
import com.didrakon.iam.governance.review.DEFAULT_SOURCES
import com.didrakon.iam.governance.review.ReviewScopeType
import com.didrakon.iam.identity.subject.SubjectRepository
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.ContentDisposition
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

data class CreateAccessReviewRequest(
    @field:NotBlank @field:Size(max = 200) val name: String,
    val scopeType: ReviewScopeType,
    val scopeOrgId: Long? = null,
    val scopeRoleId: Long? = null,
    val includeDescendants: Boolean = true,
    val privilegedOnly: Boolean = false,
    /** 비우면 DIRECT, JIT, DELEGATION */
    val sources: Set<AssignmentSourceType>? = null,
    val dueAt: Instant,
    val onOverdue: AccessReviewDecision = AccessReviewDecision.KEEP,
    /** 기한이 지나면 미결정 항목을 상위 조직 관리자에게 넘기고 더 기다리는 날수 (1~30). 비우면 이관 없이 기한에 닫는다 */
    val escalationDays: Int? = null,
)

data class AccessReviewDecisionRequest(val decision: AccessReviewDecision, @field:Size(max = 1000) val comment: String? = null)

data class AccessReviewCampaignResponse(
    val campaignId: Long,
    val name: String,
    val scopeType: String,
    val scopeOrgId: Long?,
    val scopeRoleId: Long?,
    val includeDescendants: Boolean,
    val privilegedOnly: Boolean,
    val sources: List<String>,
    val dueAt: Instant,
    val onOverdue: String,
    val escalationDays: Int?,
    val escalatedAt: Instant?,
    /** 이관까지 마친 뒤 닫는 시각. 이관이 없으면 dueAt */
    val finalDueAt: Instant,
    val status: String,
    val createdBy: Long?,
    val createdAt: Instant,
    val closedAt: Instant?,
    val total: Long,
    val pending: Long,
    val kept: Long,
    val revoked: Long,
) {
    companion object {
        fun from(p: AccessReviewProgress): AccessReviewCampaignResponse {
            val c = p.campaign
            return AccessReviewCampaignResponse(
                c.requireId(), c.name, c.scopeType.name, c.scopeOrgId, c.scopeRoleId, c.includeDescendants, c.privilegedOnly,
                c.sources.sortedBy { it.ordinal }.map { it.name }, c.dueAt, c.onOverdue.name, c.escalationDays, c.escalatedAt, c.finalDueAt, c.status.name, c.createdBy, c.createdAt, c.closedAt,
                p.total, p.counts[AccessReviewDecision.PENDING] ?: 0, p.counts[AccessReviewDecision.KEEP] ?: 0, p.counts[AccessReviewDecision.REVOKE] ?: 0,
            )
        }
    }
}

data class AccessReviewItemResponse(
    val itemId: Long,
    val campaignId: Long,
    val assignmentId: Long,
    val subjectId: Long,
    val subjectName: String,
    val empNo: String?,
    val orgName: String?,
    val roleId: Long,
    val roleCode: String,
    val roleName: String,
    val isPrivileged: Boolean,
    val scopeId: Long,
    val scopeName: String,
    val sourceType: String,
    val reviewerId: Long?,
    val reviewerName: String?,
    /** 기한 경과로 상위 관리자에게 넘긴 항목이면 넘긴 시각과 원래 검토자 */
    val escalatedAt: Instant?,
    val escalatedFromName: String?,
    val reviewRequired: Boolean,
    val assignmentValidFrom: Instant,
    val assignmentValidUntil: Instant?,
    val decision: String,
    val decidedBy: Long?,
    val decidedByName: String?,
    val decidedAt: Instant?,
    val comment: String?,
) {
    companion object {
        fun from(i: AccessReviewItem, names: Map<Long, String>) = AccessReviewItemResponse(
            i.requireId(), i.campaignId, i.assignmentId, i.subjectId, i.subjectName, i.empNo, i.orgName, i.roleId, i.roleCode, i.roleName,
            i.isPrivileged, i.scopeId, i.scopeName, i.sourceType.name, i.reviewerId, i.reviewerName, i.escalatedAt, i.escalatedFromName, i.reviewRequired,
            i.assignmentValidFrom, i.assignmentValidUntil, i.decision.name, i.decidedBy, i.decidedBy?.let { names[it] }, i.decidedAt, i.comment,
        )
    }
}

data class AccessReviewDetailResponse(val campaign: AccessReviewCampaignResponse, val items: List<AccessReviewItemResponse>)

/** 검토자에게 보이는 항목. 어느 캠페인의 언제까지인지 함께 준다 */
data class MyAccessReviewItemResponse(val campaignName: String, val dueAt: Instant, val item: AccessReviewItemResponse)

/** 접근 재검토 캠페인 관리. 검토자 본인의 할 일은 /me/access-reviews 에 있다 */
@RestController
@RequestMapping("/api/v1")
class AccessReviewApi(
    private val reviewService: AccessReviewService,
    private val subjectRepository: SubjectRepository,
) {
    @PostMapping("/access-reviews")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.REVIEW, PermissionAction.CREATE)
    fun create(@Valid @RequestBody r: CreateAccessReviewRequest): ApiResponse<IdResponse> {
        val spec = AccessReviewSpec(
            r.name, r.scopeType, r.scopeOrgId, r.scopeRoleId, r.includeDescendants, r.privilegedOnly,
            r.sources?.takeIf { it.isNotEmpty() } ?: DEFAULT_SOURCES, r.dueAt, r.onOverdue, r.escalationDays,
        )
        return ApiResponse.ok(IdResponse(reviewService.createCampaign(spec, ApiPrincipal.requireSubjectId()).requireId()))
    }

    @GetMapping("/access-reviews")
    @RequiresPermission(ApiResources.REVIEW, PermissionAction.READ)
    fun list() = ApiResponse.ok(reviewService.campaigns().map(AccessReviewCampaignResponse::from))

    @GetMapping("/access-reviews/{campaignId}")
    @RequiresPermission(ApiResources.REVIEW, PermissionAction.READ)
    fun detail(@PathVariable campaignId: Long, @RequestParam(required = false) decision: AccessReviewDecision?): ApiResponse<AccessReviewDetailResponse> {
        val campaign = reviewService.campaign(campaignId)
        return ApiResponse.ok(AccessReviewDetailResponse(AccessReviewCampaignResponse.from(campaign), itemResponses(reviewService.items(campaignId, decision))))
    }

    @PostMapping("/access-reviews/{campaignId}/close")
    @RequiresPermission(ApiResources.REVIEW, PermissionAction.APPROVE)
    fun close(@PathVariable campaignId: Long): ApiResponse<AccessReviewCampaignResponse> {
        reviewService.closeCampaign(campaignId, ApiPrincipal.requireSubjectId())
        return ApiResponse.ok(AccessReviewCampaignResponse.from(reviewService.campaign(campaignId)))
    }

    /** 관리자 결정. 검토자가 없는(조직 관리자가 없는) 항목도 여기서 정한다 */
    @PostMapping("/access-review-items/{itemId}/decide")
    @RequiresPermission(ApiResources.REVIEW, PermissionAction.APPROVE)
    fun decide(@PathVariable itemId: Long, @Valid @RequestBody r: AccessReviewDecisionRequest): ApiResponse<AccessReviewItemResponse> {
        val item = reviewService.decide(itemId, ApiPrincipal.requireSubjectId(), r.decision, r.comment)
        return ApiResponse.ok(itemResponses(listOf(item)).single())
    }

    /** 증적 내보내기. Excel 에서 한글이 깨지지 않도록 UTF-8 BOM 을 붙인다 */
    @GetMapping("/access-reviews/{campaignId}/export")
    @RequiresPermission(ApiResources.REVIEW, PermissionAction.READ)
    fun export(@PathVariable campaignId: Long): ResponseEntity<ByteArray> {
        val campaign = reviewService.campaign(campaignId).campaign
        val items = itemResponses(reviewService.items(campaignId))
        val csv = AccessReviewCsv.render(campaign, items)
        val body = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + csv.toByteArray(StandardCharsets.UTF_8)
        return ResponseEntity.ok()
            .contentType(MediaType("text", "csv", StandardCharsets.UTF_8))
            .header(
                HttpHeaders.CONTENT_DISPOSITION,
                ContentDisposition.attachment().filename("access-review-$campaignId.csv", StandardCharsets.UTF_8).build().toString(),
            )
            .body(body)
    }

    private fun itemResponses(items: List<AccessReviewItem>): List<AccessReviewItemResponse> {
        val names = subjectRepository.findAllById(items.mapNotNull { it.decidedBy }.toSet()).associate { it.requireId() to it.subjectName }
        return items.map { AccessReviewItemResponse.from(it, names) }
    }
}

/** 검토자 본인의 할 일 */
@RestController
@RequestMapping("/api/v1/me")
class MeAccessReviewApi(
    private val reviewService: AccessReviewService,
    private val subjectRepository: SubjectRepository,
) {
    @GetMapping("/access-reviews")
    @SelfService
    fun pending(): ApiResponse<List<MyAccessReviewItemResponse>> {
        val items = reviewService.pendingFor(ApiPrincipal.requireSubjectId())
        val campaigns = reviewService.campaignsById(items.map { it.campaignId }.toSet())
        return ApiResponse.ok(
            items.mapNotNull { item ->
                campaigns[item.campaignId]?.let { MyAccessReviewItemResponse(it.name, it.currentDueAt, AccessReviewItemResponse.from(item, emptyMap())) }
            },
        )
    }

    /** 배정된 검토자만 정할 수 있다. 다른 사람의 항목은 없는 것처럼 404 */
    @PostMapping("/access-review-items/{itemId}/decide")
    @SelfService
    fun decide(@PathVariable itemId: Long, @Valid @RequestBody r: AccessReviewDecisionRequest): ApiResponse<AccessReviewItemResponse> {
        val item = reviewService.decideAsReviewer(itemId, ApiPrincipal.requireSubjectId(), r.decision, r.comment)
        val names = item.decidedBy?.let { id -> subjectRepository.findById(id).map { mapOf(id to it.subjectName) }.orElse(emptyMap()) }.orEmpty()
        return ApiResponse.ok(AccessReviewItemResponse.from(item, names))
    }
}

/** 접근 재검토 증적 CSV. 시각은 KST */
internal object AccessReviewCsv {
    private val TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("Asia/Seoul"))

    private val DECISION = mapOf("PENDING" to "미결정", "KEEP" to "유지", "REVOKE" to "회수")

    fun render(campaign: AccessReviewCampaign, items: List<AccessReviewItemResponse>): String {
        val header = listOf(
            "캠페인", "항목 ID", "사번", "이름", "주 소속", "역할 코드", "역할", "특권", "범위", "출처", "할당 시작(KST)", "할당 종료(KST)",
            "재검토 표시", "검토자", "이관 전 검토자", "이관 시각(KST)", "결정", "결정자", "결정 시각(KST)", "의견",
        )
        val rows = items.map { i ->
            listOf(
                campaign.name, i.itemId.toString(), i.empNo, i.subjectName, i.orgName, i.roleCode, i.roleName, yesNo(i.isPrivileged), i.scopeName,
                i.sourceType, time(i.assignmentValidFrom), time(i.assignmentValidUntil), yesNo(i.reviewRequired), i.reviewerName ?: "관리자",
                i.escalatedAt?.let { i.escalatedFromName ?: "관리자" }, time(i.escalatedAt),
                DECISION[i.decision] ?: i.decision,
                i.decidedByName ?: if (i.decidedAt != null && i.decidedBy == null) "자동(기한·마감)" else i.decidedBy?.toString(),
                time(i.decidedAt), i.comment,
            )
        }
        return (listOf(header) + rows).joinToString("\r\n", postfix = "\r\n") { row -> row.joinToString(",") { cell(it) } }
    }

    private fun yesNo(value: Boolean) = if (value) "예" else "아니오"

    private fun time(value: Instant?) = value?.let { TIME.format(it) }

    /** 따옴표·쉼표·줄바꿈은 감싸고, 수식으로 해석될 수 있는 값(=,+,-,@ 로 시작)은 앞에 ' 를 붙인다 (CSV injection 방지) */
    private fun cell(value: String?): String {
        val raw = value.orEmpty()
        val safe = if (raw.isNotEmpty() && raw[0] in "=+-@\t\r") "'$raw" else raw
        return if (safe.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"" + safe.replace("\"", "\"\"") + "\"" else safe
    }
}
