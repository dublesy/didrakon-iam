package com.didrakon.iam.api.audit

import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.audit.history.PolicyChangeHistory
import com.didrakon.iam.audit.history.RoleChangeHistory
import com.didrakon.iam.audit.query.AuditEventView
import com.didrakon.iam.audit.query.AuditQueryService
import com.didrakon.iam.audit.query.AuditSearch
import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.authz.role.PermissionAction
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

data class RoleHistoryResponse(
    val historyId: Long,
    val roleId: Long,
    val changeType: String,
    val assignmentId: Long?,
    val changedBy: Long?,
    val reason: String?,
    val changedAt: Instant,
) {
    companion object {
        fun from(h: RoleChangeHistory) = RoleHistoryResponse(h.requireId(), h.roleId, h.changeType.name, h.assignmentId, h.changedBy, h.reason, h.changedAt)
    }
}

data class PolicyHistoryResponse(
    val historyId: Long,
    val oldVersion: Int?,
    val newVersion: Int?,
    val changedBy: Long?,
    val changeReason: String?,
    val oldValue: String?,
    val newValue: String?,
    val changedAt: Instant,
) {
    companion object {
        fun from(h: PolicyChangeHistory) =
            PolicyHistoryResponse(h.requireId(), h.oldVersion, h.newVersion, h.changedBy, h.changeReason, h.oldValue, h.newValue, h.changedAt)
    }
}

@RestController
@RequestMapping("/api/v1/audit")
class AuditApi(private val auditQueryService: AuditQueryService) {
    /** 기간 [from, to) 필수. 최신순 */
    @GetMapping("/events")
    @RequiresPermission(ApiResources.AUDIT, PermissionAction.READ)
    fun events(
        @RequestParam from: Instant,
        @RequestParam to: Instant,
        @RequestParam(required = false) subjectId: Long?,
        @RequestParam(required = false) types: Set<AuditEventType>?,
        @RequestParam(defaultValue = "100") limit: Int,
    ): ApiResponse<List<AuditEventView>> =
        ApiResponse.ok(auditQueryService.search(AuditSearch(from, to, subjectId, types.orEmpty(), limit)))

    @GetMapping("/role-history/{subjectId}")
    @RequiresPermission(ApiResources.AUDIT, PermissionAction.READ)
    fun roleHistory(@PathVariable subjectId: Long) = ApiResponse.ok(auditQueryService.roleHistory(subjectId).map(RoleHistoryResponse::from))

    @GetMapping("/policy-history/{policyId}")
    @RequiresPermission(ApiResources.AUDIT, PermissionAction.READ)
    fun policyHistory(@PathVariable policyId: Long) = ApiResponse.ok(auditQueryService.policyHistory(policyId).map(PolicyHistoryResponse::from))
}
